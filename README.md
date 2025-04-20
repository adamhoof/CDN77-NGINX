# NGINX task

**Contents** <br>
[Research](#research) <br>
[1) - NGINX cache lookup key analysis](#1---nginx-cache-lookup-key-analysis) <br>
[2) - NGINX X-Cache-Key header addition](#2---nginx-x-cache-key-header-addition) <br>
[3) - DNS wildcard algorithm](#3---dns-wildcard-algorithm) <br>
[4) - Bonus Lua module API extension](#4---bonus-lua-module-api-extension) <br>
[Approximate time requirements](#approximate-time-requirements) <br>

## Research

NGINX -> high performance, opensource software which can function as a web server, reverse proxy with load balancer, cache etc. -> CONFIGURABLE. Can handle heavy load, event driven arch. <br>
Forward vs Reverse proxy -> acts on behalf of the client, eg. VPN that hides client IP vs acts on behalf of the server, eg. reverse proxy with load balancing, caching etc. <br>
#### Configuration
- Defined in a nginx.conf
- Scopes/Context: by default everything is in a "main" scope/context, where all general settings are configured. We put other scopes/contexts and directives/commands inside.
- Directives/Commands: basically specific settings with arguments, eg. how many connections per worker can we have, http routing config, cache, ...
- This approach of scopes and commands seems to provide a really good configuration granularity.

#### Development guide most important parts
- Architecture goes like this: Small core + pluggable modules. 
- Uses its own memory allocation method
  - Allocate larger chunk (pool) of memory first.
  - Use ngx_palloc(pool, size) to request memory from this pre-allocated space. SPEED! (similar in concept to Go memory arena)
  - The deletion is also "automated", since the pool has the ownership over the memory! 
- Has its own data types -> ngx_str_t, ngx_uint_t, uintptr_t, ngx_array_t, ngx_list_t... cool!
- Directives/commands in code are represented using _ngx_command_t_, specifying name, args, allowed contexts, handler function of a single directive.
  - Allowed contexts examples (where does the parser accept specific directives/commands): NGX_MAIN_CONF (top level), NGX_HTTP_MAIN_CONF (http block), NXG_HTTP_SRV_CONF (http -> server block)
- Internal configuration structure in code by subsystem, module and scope
  - Generic: `ngx_<subsystem>_<module>_<scope>_conf_t`
    - subsystem -> major configuration context/scope (http{}, stream{})
    - module -> functional module providing directives/commands within the subsystem (core{}, proxy{}, ssl{})
    - scope -> configuration context/scope within the subsystem
      - main -> top level of the subsystem (http{ **->here<-** }, NOT to be confused with the top level "main" context ("main" { **->!here<-** ... http{} ...})
      - srv -> inside server{} (http{server{ **->here<-** }})
      - ...
    - Examples:
  - ngx_http_<module>_main_conf_t: stores settings for `<module>` directives defined directly inside the http { **->here<-** } block
  - ngx_http_<module>_srv_conf_t: stores settings for `<module>` directives defined inside http { server { **->here<-** } } block
  - ngx_http_proxy_srv_conf_t: stores settings for proxy directives defined inside http { server { **->here<-**} } block

## 1) - NGINX cache lookup key analysis

### Thought process (literary):

1. Figure out where to even look in the docs, the task is about cache, let's search cache.
    - Ok there are a couple of cache-related things, we are specifically interested in how cache key works in there, so perhaps proxy_cache_key link might be correct.
    - So this is only an overview of how to configure things -> nginx is opensource, look into the code.
2. Code exploration
    - ngx_http_proxy_module.c looks legit, search cache keyword, found ngx_http_proxy_cache_key function.
      - A bunch of mumbo jumbo here, looks like the function takes in some config and parses it into an internal complex compiled value. from future --> this is responsible for creating the **parsed** "key template" from proxy_cache_key directive for later use (request comes, evaluate out it's variables based on this "key template", build the final keys string, which is then hashed) <-- from future
      - **To make sense of this all, we gotta go back and dig a little bit more into how nginx works under the hood in general before proceeding.** (added to [Development guide most important parts](#development-guide-most-important-parts)) <br>
    - **QUESTIONS 1 + 2: Podle jakého klíče nginx v cache vyhledává + jak se tento klíč vypočítává?** <br>
      - What can the cache even look for? -> Generally speaking some response from server, in this case HTTP response.
      - Issue: Storing big responses in RAM would not be ideal, deplete memory pretty fast. Storing it on a disk and looking up there would be slow.
      - Solution:
        - Responses must go on a disk to not deplete RAM. For fast lookups, we will store the key (or more metadata) in a RAM.
        - => We will need to search some interaction between the cache and filesystem (everything is a file, said Tux), since the response will be stored on a disk and we need to calculate a key representing the presence of this response.
      - Found `ngx_http_file_cache.c` file -> [ngx_http_file_cache_create_key](https://github.com/nginx/nginx/blob/b6e7eb0f5792d7a52d2675ee3906e502d63c48e3/src/http/ngx_http_file_cache.c#L228)
        1. Here we can see that `ngx_http_cache_t*` is stored in the request `c = r->cache;`, which holds cache related information for this specific request (ie. GET /image.png). Must have been prepopulated in earlier processing.
        2. The crc32 and md5 are initialized for checksum (error detection) and hashing purposes `ngx_crc32_init(c->crc32);` `ngx_md5_init(&md5);`
        3. Iterate over the key components ( apply func md5(unique key components) -> unique, deterministic output hash ) stored in c->keys, print each for debugging purposes, update crc32 and md5 calculation with this current key component. The keys are the taken from proxy_cache_key directive, which defaults to `$scheme$proxy_host$request_uri` but can be changed.
        4. Calculate offset to house the nginx internal header containing metadata.
        5. Finalize the crc32 and md5 calculation. Important for us here is the md5 calculation, which stores the result into c->key as we can see in the ngx_md5.c -> [ngx_md5_final](https://github.com/nginx/nginx/blob/master/src/core/ngx_md5.c#L62)
        6. Now c->cache holds the key (calculated unique, deterministic hash)!
    - **QUESTION 3: K čemu se používá?**
        - In Qs 1 + 2 we found out how this key is calculated and that it is used for cache lookup.
        - But the hint in the task description tells us "jméno souboru v cache", which is a strong indicator of the key either being the full filename or part of it.
        - I'm wondering, where is this whole caching process or atleast part of it located in the codebase? Inside the ngx_http_file_cache.c are individual module functions, but it needs to be called from somewhere. Might actually lead us to the part where it writes the key as a filename or part of it, as the hint points us.
          - Digging where else `ngx_http_file_cache_create_key(ngx_http_request_t *r)` is used, found `ngx_http_upstream.c` -> [ngx_http_upstream_cache(ngx_http_request_t *r, ngx_http_upstream_t *u)](https://github.com/nginx/nginx/blob/b6e7eb0f5792d7a52d2675ee3906e502d63c48e3/src/http/ngx_http_upstream.c#L882).
          - Inside, this caught my eye [ngx_http_file_cache_open](https://github.com/nginx/nginx/blob/b6e7eb0f5792d7a52d2675ee3906e502d63c48e3/src/http/ngx_http_file_cache.c#L265), leads back to the http_file_cache.c, aight :D
          - But looking through, it seems we hit it! It calls [ngx_http_file_cache_name](https://github.com/nginx/nginx/blob/b6e7eb0f5792d7a52d2675ee3906e502d63c48e3/src/http/ngx_http_file_cache.c#L994), where the filename generation happens! 
            1. It checks if the cache already has the name generated by doing: `if (c->file.name.len)`
            2. Calculates the required length for the full cache path string: `c->file.name.len = path->name.len + 1 + path->len + 2 * NGX_HTTP_CACHE_KEY_LEN;`
            3. Allocate memory from pool to buffer based on this path string (don't forget to protecc ma boi null terminator): `c->file.name.data = ngx_pnalloc(r->pool, c->file.name.len + 1);`
            4. Copy base cache dir path into the buffer: `ngx_memcpy(c->file.name.data, path->name.data, path->name.len);`
            5. **Convert the c->key to 32 char HEX string representation:** `p = ngx_hex_dump(p, c->key, NGX_HTTP_CACHE_KEY_LEN);`
        - Still wondering about the broader process though, looking around, these lookin interesting:
          - Found this [ngx_http_file_cache_add_file](https://github.com/nginx/nginx/blob/444954abacef1d77f3dc6e9b1878684c7e6fe5b3/src/http/ngx_http_file_cache.c#L2219) which seems to aggregate metadata about existing cache files, it calls ->
            - -> [ngx_http_file_cache_add](https://github.com/nginx/nginx/blob/444954abacef1d77f3dc6e9b1878684c7e6fe5b3/src/http/ngx_http_file_cache.c#L2273)
            1. It locks shared memory rbtree (rbtree because I looked into the lookup func, shared based on the fact the func is locking it and it is a memory area = > shared memory). from future ->> Bruh the name is shmtx and shpool, what could the sh possibly mean xddd <-- from future
            2. Looks for a specific `ngx_http_file_cache_node_t` (`ngx_http_file_cache_lookup`), whose structure is defined [here](https://github.com/nginx/nginx/blob/444954abacef1d77f3dc6e9b1878684c7e6fe5b3/src/http/ngx_http_cache.h#L39), pretty big boy, this is the structure representing metadata record for a cache entry
            3. ... This is another usecase of this key, although not disjunct with the others - indexing, finding, adding, deleting metadata nodes in the shared memory rbtree
          - Wait this might actually give us the answer for **QUESTION 4: Jaká je jeho lokace z hlediska datových struktur?** - KEY IS METADATA AND WE ARE LOOKING AT METADATA NODES! Where EXACTLY is the key stored then?
            - Let's inspect the nodes again:
              - What the hell is this inside the `ngx_http_file_cache_node_t` **--->** `u_char key[NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t)];` 
                - It clearly stores the key, but perhaps just a part of it? And judging by the sizeof subtraction, rest of the key might be stored in the `rbtree_node_t->ngx_rbtree_key_t`.
              - Hmm now I remembered this lines existence in the `ngx_http_file_cache_lookup` **--->** `ngx_memcpy((u_char *) &node_key, key, sizeof(ngx_rbtree_key_t));`, 
                - => **it means that the FIRST part of the key is stored in the `ngx_rbtree_node_t`? The one inside `ngx_http_file_cache_node_t->ngx_rbtree_node_t`**
              - This piece of code inside the `ngx_http_file_cache_lookup` is also interesting **--->** `rc = ngx_memcmp(&key[sizeof(ngx_rbtree_key_t)], fcn->key, NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));` 
                - => it means that before, it compared ONLY the first part of the key and if it matches, it now takes the rest of the key `fcn->key` and compares it to the looked up one and `if (rc == 0)` we found it and return the `ngx_http_file_cache_node_t` pointer, named fcn.
                - => **it means that the REST is stored inside the `ngx_http_file_cache_node_t->key`.**
        - We found the answer, but WHY is the key split up like this? There must be a reason for that Let's google a bit
          - OH so the `ngx_rbtree_node_t->key` part (FIRST part of the key) is a size of native integer type (`ngx_uint_t`), which means super fast "if match" comparisons! DAMNNN
            - Issue: But this would not ensure the key is EXACTLY the one we are looking for (though most of the time probably would be), since only the first part is checked
            - Fix: Here is where the second "if match" check comes in. It checks the `ngx_http_file_cache_node_t->key` (REST of the key) and if it matches, return node pointer, if not, continue traversing the rbtree, repeat, done!
          - How it is done is nicely seen on this line here `ngx_memcpy((u_char *) &node_key, key, sizeof(ngx_rbtree_key_t));`
            - `ngx_rbtree_key_t` is `ngx_uint_t` => we are copying first `sizeof(ngx_uint_t)`bytes of the looked up key into the `node_key`. 
            - Now we can compare integer value of those bytes which is fast af! -> `if (node_key < node->key) { node = node->left; continue; }`
        - This is beyond the question scope, but the rbtree is in the shared memory area, which is stored in a RAM => not persistent. This would mean the cache metadata is lost after nginx reboots!
          - Did a little research and turns out that the rbtree is re-built upon start by scanning the cache directory (here is where the actual cache responses are placed). As we found earlier in Q3 answer, the filenames are the key, that is pretty helpful!
          - Also, remember our boi internal nginx cache metadata header space allocation from Question 1 + 2 -> cache_create_key -> point d.? That is where the metadata are placed persistently, and from where we can extract them, since the header is a part of the file itself!
        - Haha I can't stop digging into this, but it would seem like the `ngx_http_cache_t` also holds the key as we can see [here](https://github.com/nginx/nginx/blob/444954abacef1d77f3dc6e9b1878684c7e6fe5b3/src/http/ngx_http_cache.h#L65)
          - If we look into [ngx_http_file_cache_new](https://github.com/nginx/nginx/blob/444954abacef1d77f3dc6e9b1878684c7e6fe5b3/src/http/ngx_http_file_cache.c#L176), the `ngx_http_cache_t` is allocated from requests pool `c = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_t));`, so when request is processed POOF, GONE => TEMPORARY storage where we happen to put the key for some accessibility reasons, probably.
            - An example flow goes like this: [finalize_request](https://github.com/nginx/nginx/blob/444954abacef1d77f3dc6e9b1878684c7e6fe5b3/src/http/ngx_http_request.c#L2523C1-L2523C26) -> [terminate_request](https://github.com/nginx/nginx/blob/444954abacef1d77f3dc6e9b1878684c7e6fe5b3/src/http/ngx_http_request.c#L2710) -> [close_request](https://github.com/nginx/nginx/blob/444954abacef1d77f3dc6e9b1878684c7e6fe5b3/src/http/ngx_http_request.c#L3726) -> [free_request](https://github.com/nginx/nginx/blob/444954abacef1d77f3dc6e9b1878684c7e6fe5b3/src/http/ngx_http_request.c#L3759) -> [r->pool gets freed](https://github.com/nginx/nginx/blob/444954abacef1d77f3dc6e9b1878684c7e6fe5b3/src/http/ngx_http_request.c#L3849)
          - But if we look back into [ngx_http_file_cache_add](https://github.com/nginx/nginx/blob/444954abacef1d77f3dc6e9b1878684c7e6fe5b3/src/http/ngx_http_file_cache.c#L2273), we allocate from the cache shared pool `fcn = ngx_slab_calloc_locked(cache->shpool,sizeof(ngx_http_file_cache_node_t));` => PERSISTENT (during runtime)
            - This shared memory area has a completely different lifecycle as we can see here, it gets allocated when the file cache is [initialized](https://github.com/nginx/nginx/blob/444954abacef1d77f3dc6e9b1878684c7e6fe5b3/src/http/ngx_http_file_cache.c#L83), I bet it does not get destroyed very soon.
    - **QUESTION 5: Jaká je jeho lokace z hlediska paměťového umístění (jak na něj nahlíží OS)**
      - Let's recap what previous answers told us:
        - The key is stored in RAM in a shared memory area for active lookups. OS sees it as 16 bytes. 
        - The key is stored on a disk for persistence. OS sees this as part of a filename string, which is fs metadata used to locate corresponding file data blocks on the disk.
            - NOTE: Everything is really just bytes in the end, but I think this illustrates the point better role-wise.

## 2) - NGINX X-Cache-Key header addition
### Thought process (literary):
1. First let's consider the constraints
   - The X-Cache-Key must be the calculated key from 1), Questions 1 + 2.
     - After we even figure out where to start, this should not be super hard - we already know where and how it is calculated, can borrow the function if needed. 
   - The header must be sent to the client (in a response to the previous request), not to the origin.
     - This is a little confusing, A lot of questions arise. 
       - What process is this in the codebase? Is it there at all?
       - How to add a header, probably some module function?
       - How to tell where the response is going (client vs origin server)?
       - Reeeee
   - Lua or openrest modules are not allowed
     - Ok
2. Code exploration
   - Check out how headers are added
     - Found [ngx_http_add_header](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_headers_filter_module.c#L537), does not do much, just appends a header.
     - Found [ngx_http_headers_filter_commands](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_headers_filter_module.c#L100), this looks like mapping conf file **directive <-> in-code action**.
       - Inside we can see `ngx_string("add_header")`, `ngx_string("add_trailer")` and that they correspond to [ngx_http_headers_add](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_headers_filter_module.c#L775)
       - The `ngx_http_headers_add` sets `ngx_http_add_header` as a handler ( `if (headers == &hcf->headers) { hv->handler = ngx_http_add_header;` ).
       - Let's consolidate the overall flow:
         1. A directive is written into `nginx.conf` -> `add_header <key> <value>` (ie. add_header X-Content-Source "CMS")
         2. `ngx_http_headers_add` parses those directives during configuration loading.
         3. `ngx_http_headers_add` sets handlers for those directives accordingly (like the `ngx_http_add_header`). I really like this approach!
         4. Those handlers are used to do... hmmm, what exactly? Well to handle, but what and when?
            - A request when it comes and we want to process its headers.
            - It must also be after the step of calculating the key, otherwise we would have nothing to add :D
            - Umm looking at it, the first 2 points contradict each other. When the request comes and we have not processed anything... how can we use the CALCULATED key? => There is some other phase that processes the request before it touches the headers.
     - The last point hinted me to specifically search for some type of phases, if they even exist. Turns out they do!
       - Phases enum here [ngx_http_core_module.h -> ngx_http_phases](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/ngx_http_core_module.h#L109)
       - Searching for phases further, found [ngx_http_core_module.c -> ngx_http_handler](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/ngx_http_core_module.c#L865)
       - And more of the actual phase handlers that the `ngx_http_phases` defines. (`ngx_http_core_rewrite_phase`, `ngx_http_core_post_rewrite_phase`, `ngx_http_core_access_phase`...). They are called in a chain like manner.
       - **But hold on... these are request processing related. Adding a custom header will be in some response building phase no???**
   - So let's take it from the other side, is there a point where we send response?
     - Found [ngx_http_send_response](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/ngx_http_core_module.c#L1760), ahaaaaa here we go, already see a plenty of header related stuff.
       - It calls [ngx_http_send_header](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/ngx_http_core_module.c#L1839)
         - Why are we sending header on its own? -> Response header is sent before response body.
         - This function calls `ngx_http_top_header_filter`, what is that? -> The call initiates a chain process of filters, each doing their part in modifying, adding... the headers. **I believe this is the key to solving this task!**
       - It returns [ngx_http_output_filter](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/ngx_http_core_module.c#L1861)
         - Why? -> Similar to the header filter chain, but this triggers the response body filter chain.
         - Since we care about the headers, response body manipulation is not that important for us, but good to know.
   - Great so the next step is to create our own filter, which appends the calculated X-Cache-Key and then figure how to inject it into the filter chain.
     - Let's look at some existing filters to see how things work.
       - Found this [ngx_http_userid_filter_module](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_userid_filter_module.c). Looks like a whole module?
         - This is familiar, a mapping of conf directives <-> in-code action [ngx_http_userid_commands](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_userid_filter_module.c#L120). We don't need this, not introducing any new directives.
         - HTTP module context [ngx_http_userid_filter_module_ctx](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_userid_filter_module.c#L189). **This defines how the module interacts with HTTP configuration scopes (so what to do when ie. server{}, location{} is created). As well as what to do in pre/post configuration (that means either pre/post directives have been processed).**
         - Top level nginx module definition, more general [ngx_module_t](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_userid_filter_module.c#L204). **This defines version, context (the one above), commands, module type and what to do in the initialization/exit server-wide events.**
         - This is the coordinator of the filter process [ngx_http_userid_filter](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_userid_filter_module.c#L227).
         - Some specific functions to the userid that the coordinator uses (get_uid, set_uid, create_uid)... this will be the appending logic in our case.
         - Now we are talking, this is DEFINITELY important, it manipulates the header filter chain! [ngx_http_userid_init](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_userid_filter_module.c#L777). 
3. Custom module implementation
   - So we know that the filter can be injected not by just implementing some function and calling it, but plugging in a module that says "hey, I have a header filter". Makes sense, nginx is **small core + pluggable modules**. Everything is a module.
     - So far it is unclear to me how to define the `ngx_module_t` and `ngx_http_module_t`, let's search what each does and break it down.
       - `ngx_module_t`: 
         - Server-wide events -> Since this is just a runtime filter that appends a header, nothing special needs to be done when a server-wide event occurs, so all NULL.
         - Version, padding -> Will just copy from the userid filter module.
         - Commands -> We do not introduce any new directives, so NULL.
         - Module context -> Just a pointer to the struct `ngs_http_module_t` below.
         - Module type -> Clearly an HTTP module.
       - `ngx_http_module_t`:
         - preconfiguration -> nothing, we do not need to do anything before directives processing.
         - postconfiguration -> this is crucial and needs to be configured, here we inject our filter!
         - Scope interaction -> there is no scope-dependent behavior I would say, so NULL for all of them.
    
## 3) - DNS wildcard algorithm
## 4) - Bonus Lua module API extension

## Approximate time requirements:
**Research** (topics, terms): 4h <br>
**1) - NGINX cache lookup key analysis**: 8h <br>
**2) - NGINX X-Cache-Key header addition**: 8h <br>
**3) - DNS wildcard algorithm**<br>
**4) - Bonus Lua module API extension**<br>
**Documentation** (thought process and ideas capture): 10h <br>
