# NGINX task

**Contents** <br>
[Research](#research) <br>
[1) - NGINX cache lookup key analysis](#1---nginx-cache-lookup-key-analysis) <br>
[2) - NGINX X-Cache-Key header addition](#2---nginx-x-cache-key-header-addition) <br>
[3) - DNS wildcard algorithm](#3---dns-wildcard-algorithm) <br>
[Approximate time requirements](#approximate-time-requirements) <br>

## Research

NGINX -> high performance, opensource software which can function as a web server, reverse proxy with load balancer, cache etc. -> CONFIGURABLE. Can handle heavy load, event driven arch. <br>
Forward vs Reverse proxy -> acts on behalf of the client, eg. VPN that hides client IP vs acts on behalf of the server, eg. reverse proxy with load balancing, caching etc. <br>
DNS zone -> Part of internet's domain name system that one organization is responsible for managing => owns all the DNS records for the domains within that part. (ie. `example.com` DNS zone owns records like `www.example.com`, `ftp.example.com`...).
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
### Figure out where to even look in the docs, the task is about cache, let's search cache.
- Ok there are a couple of cache-related things, we are specifically interested in how cache key works in there, so perhaps proxy_cache_key link might be correct.
- So this is only an overview of how to configure things -> nginx is opensource, look into the code.
### Code exploration
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
### Task specs and observations
- The X-Cache-Key must be the calculated key from 1), Questions 1 + 2.
  - After we even figure out where to start, this should not be super hard - we already know where and how it is calculated, can borrow the function if needed. 
- The header must be sent to the client (in a response to the previous request), not to the origin. Lil confusing, a lot of questions. 
    - What process is this in the codebase? Is it there at all?
    - How to add a header, probably some module function?
    - How to tell where the response is going (client vs origin server)?
    - Reeeee
- Lua or openrest modules are not allowed
  - Ok
### Code exploration
##### Check out how headers are added
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
##### Let's take it from the other side, is there a point where we send response?
- Found [ngx_http_send_response](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/ngx_http_core_module.c#L1760), ahaaaaa here we go, already see a plenty of header related stuff.
  - It calls [ngx_http_send_header](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/ngx_http_core_module.c#L1839)
    - Why are we sending header on its own? -> Response header is sent before response body.
    - This function calls `ngx_http_top_header_filter`, what is that? -> The call initiates a chain process of filters, each doing their part in modifying, adding... the headers. **I believe this is the key to solving this task!**
  - It returns [ngx_http_output_filter](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/ngx_http_core_module.c#L1861)
    - Why? -> Similar to the header filter chain, but this triggers the response body filter chain.
    - Since we care about the headers, response body manipulation is not that important for us, but good to know.
##### Next step is to create our own filter
- We need to figure out how to append the calculated key and how to inject the filter into the filter chain
- Let's look at some existing filters to see how things work.
  - Found this [ngx_http_userid_filter_module](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_userid_filter_module.c). Looks like a whole module?
    - This is familiar, a mapping of conf directives <-> in-code action [ngx_http_userid_commands](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_userid_filter_module.c#L120). We don't need this, not introducing any new directives.
    - HTTP module context [ngx_http_userid_filter_module_ctx](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_userid_filter_module.c#L189). from future --> This defines how the module interacts with HTTP configuration scopes (so what to do when ie. server{}, location{} is created). It also defines what to do in pre/post configuration (that means either pre/post directives have been processed). <-- from future
    - Top level nginx module definition, more general [ngx_module_t](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_userid_filter_module.c#L204). from future --> This defines version, context (the one above), commands, module type and what to do in the initialization/exit server-wide events. <-- from future
    - This is the filter itself, here it serves as a coordinator of individual functionalities [ngx_http_userid_filter](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_userid_filter_module.c#L227).
    - Some specific functions to the userid that the coordinator uses (get_uid, set_uid, create_uid)... this will be the appending logic in our case.
    - Now we are talking, this is DEFINITELY important, it manipulates the header filter chain! [ngx_http_userid_init](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_userid_filter_module.c#L777). 
### Custom module implementation
##### Preparation
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
- Alright now it is time to start the implementation. Let's checkout [NGINX contributing](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/CONTRIBUTING.md) guide to see how we should structure the code etc.
  - Here is [code style](https://nginx.org/en/docs/dev/development_guide.html#code_style). Ehhh first common pitfalls point is "Writing a C module -> do not try to write one if you do not have to". Hope I did not miss anything :D But the task confirms it can't be done with a simple configuration so guess we good.
    - Damn this document is actually an awesome overview. There are some very relevant chapters on how to build filter modules, response header info, code style, tips.
##### Setup dev env
- We need to compile [from source](https://docs.nginx.com/nginx/admin-guide/installing-nginx/installing-nginx-open-source/#sources) since we wanna add a custom module.
  - Download dependencies as the guide says - pcre, zlib, openssl. Gcc and make are a must ofc!
  - Download nginx project (stable), unpack.
  - Before running `./configure`, we need to specify a config file so that nginx can register it, see the config file [here](https://github.com/adamhoof/CDN77-NGINX/blob/master/config). Inspired from the docs example [Building filter module](https://nginx.org/en/docs/dev/development_guide.html#http_building_filter_modules).
  - Run `./configure --prefix="/opt/nginx-custom" --with-http_ssl_module --add-module="/path/to/custom/module"`
    - [prefix](https://docs.nginx.com/nginx/admin-guide/installing-nginx/installing-nginx-open-source/#configuring-nginx-paths): set install dir to prevent possible clash with other nginx installation,
    - [ssl](https://docs.nginx.com/nginx/admin-guide/installing-nginx/installing-nginx-open-source/#including-modules-not-built-by-default): https is the default nowadays and I noticed ssl is not included by default => no https.
    - [add-module](https://docs.nginx.com/nginx/admin-guide/installing-nginx/installing-nginx-open-source/#including-third-party-modules): tell nginx to count our custom 3rd party module in.
  - Seems like the `./configure` is not complaining about our module, output part -> "`adding module in /path/to/custom/module`" "` +  was configured`"
  - `make`! This fails now, but that is ok, the module .c file is empty. Important is that it did not fail on other steps.
  - Inside the custom module, create CMakeLists.txt and reference the downloaded nginx project => makes static analysis work in CLion IDE (leave me ok, zoomers like CMakeLists.txt more than Makefile), check it out here [here](https://github.com/adamhoof/CDN77-NGINX/blob/master/CMakeLists.txt).
    - The `include_directories` of this CMakeLists.txt is what I saw in the make output, probably a good starter -> `... -I src/core -I src/event -I src/event/modules -I src/event/quic -I src/os/unix -I objs -I src/http -I src/http/modules ...`
##### Coding time
- So we will start with what we already figured out earlier, the module struct definitions. Before sleep [commit](https://github.com/adamhoof/CDN77-NGINX/commit/0bfe24d59604c0a07d96d1dbcb11efc17dc21d6f).
- Now let's follow the example userid filter module again and create the post-configuration init function. [Commit](https://github.com/adamhoof/CDN77-NGINX/commit/23d9200f5ff3f69fe829db6725d79ea13b51cd47).
- Next step is to create the actual filter function. This is the main logic part.
  1. The nginx dev guide tells us to put declarations at the top, so we do that.
  2. --> from future THIS IS LATER CORRECTED, SHOULD BE CALLEED LAST <-- from future. Call the next header filter first to follow the chain, if fails return. `rc = ngx_http_next_header_filter(r);` `if (rc != NGX_OK) { return rc; }`.
  3. Process only the main request, no sub-requests. `if (r != r->main) { return rc; }`.
  4. Check cache context existence `c = r->cache;` `if (c == NULL) { return rc; }`.
     - Issue: CLion does not see `r->cache`. Hmm, so when `./configure` was invoked, it definitely compiled with the cache module.
       - The problem is that CLion evaluates `#if (NGX_HTTP_CACHE) ngx_http_cache_t *cache; #endif` as **false** and thus it does not see `ngx_http_cache_t` inside `r->cache` request.
       - But the CMakeLists.txt probably does not have a chance to know how we compiled nginx, we need to tell him about this flag being **true**.
     - Fix: Add `target_compile_definitions(ngx_http_x_cache_key_filter_module PRIVATE NGX_HTTP_CACHE=1)` to CMakeLists.txt. -> Works!
  5. Allocate memory from the request's pool, check...  `hex_key_ngx_str.data = ngx_pnalloc(r->pool, hex_key_str_len);` `if (hex_key_ngx_str.data == NULL) {...` 
     - Guide on [memory management -> pool](https://nginx.org/en/docs/dev/development_guide.html#memory_management) tells us "ngx_pnalloc(pool, size) — Allocate unaligned memory from the specified pool. **Mostly used for allocating strings.**"
  6. Hex dump the 16 byte binary key into 32 byte hex string (MD5 hash is 128 bits == 32 bytes).
     - The conversion is like this because each binary byte is 8 bits and one hex char represents only 4 bits => 2x the space.
  7. Add a new header `h = ngx_list_push(&r->headers_out.headers);`
  8. Example [here](https://nginx.org/en/docs/dev/development_guide.html#http_response) shows how to fill the header (`h->hash`, `h->key`...) and the value is our hex key string.
  9. Done, [commit](https://github.com/adamhoof/CDN77-NGINX/commit/cb7a803c9360b46a9bdfd5751168c7002f8e396b)
##### Time to test
- Repeat the nginx project compilation process
  - cleanup first `make clean`
  - same as before `./configure --prefix="/opt/nginx-custom" --with-http_ssl_module --add-module="/path/to/custom/module"`, no errors again, expected (config did not change) but good
  - `make`, this time it seems everything is intact
      - `... copmilation flags ... -I src/core -I src/event -I src/event/modules ... more ... -o objs/addon/ngx_http_x_cache_key_filter_module/ngx_http_x_cache_key_filter_module.o /path/to/custom/module`
- Create `nginx.conf` file, checkout [here](https://github.com/adamhoof/CDN77-NGINX/blob/master/nginx.conf).
  - Basic conf taken from [Beginner's guide](https://nginx.org/en/docs/beginners_guide.html#proxy).
  - Advanced proxy conf in this [article](https://betterstack.com/community/questions/how-to-setup-nginx-as-caching-reverse-proxy/).
  - Looked up what the directives mean in [ngx_http_proxy_module docs](https://nginx.org/en/docs/http/ngx_http_proxy_module.html). 
  - SSL conf in [nginx admin guide](https://docs.nginx.com/nginx/admin-guide/security-controls/securing-http-traffic-upstream/).
    - Generation of self signed certificates needs to be done to enable secure connection to our proxy.
    - `openssl req -x509 -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx-selfsigned.key -out /etc/nginx/ssl/nginx-selfsigned.crt`
- Run nginx with our nginx.conf file
  - `sudo ./objs/nginx -c /path/to/nginx.conf`
  - `ps -A | grep nginx` confirms nginx is running
- Make a test request to see if proxy works at all
  - `curl -k -I https://localhost:8443/`, this should produce an OK response and a cache MISS
    - `-k` aka `--insecure` to allow self-signed certs to work 
    - `-I` aka `--head` to list headers, this is where our cache key should appear
  - The output looks good, but there is no X-Cache-Key, something is wrong: 
    - `HTTP/1.1 200 OK
      Server: nginx/1.26.3
      Date, Content Type, ....`
- Make another test request to see if our cache works at all
  - `curl -k -I https://localhost:8443/`, this should produce an OK response and a cache HIT
  - The cache seems to have been involved telling by the speed of response, but there is no information in the output about it.
  - Where to check? LOGS. There seem to be 2 main log outputs, access and error. [Configuring Logging](https://docs.nginx.com/nginx/admin-guide/monitoring/logging/).
    - **access log** tells us little by default, but there is a way to format it as the guide says, [updated nginx.conf commit](https://github.com/adamhoof/CDN77-NGINX/commit/1785825860f882df2cce2cb6b26d404e182de7d9).
      - Before -> `127.0.0.1 - - [22/Apr/2025:08:07:17 +0200] "HEAD / HTTP/1.1" 200 0 "-" "curl/8.9.1"`
      - After -> `127.0.0.1 [22/Apr/2025:08:20:15 +0200] "HEAD / HTTP/1.1" 200"curl/8.9.1"cache_status=HIT`. NICE!
    - **error log** tells us quite a bit, here is where our custom module logs should go as well.
      - We know that cache works just fine from the access log, so there must be a problem with our custom module.
      - Let's filter the error log to see our log messages -> `cat /opt/nginx-custom/logs/error.log | grep "XCKF"`
        - Issue: Hmmm, empty. So the module probably did not load at all or there is some other issue.
        - Fix1: Turns out to see debug, we need to compile with the option `--with-debug`, I am not surprised :D
        - Fix2: It is interesting that debug message inside `ngx_http_x_cache_key_filter_init` doesn't get logged when called using `ngx_log_debug0(NGX_LOG_DEBUG_HTTP,...)`, even though for the `ngx_http_x_cache_key_header_filter` function, it works just fine. Changing the call to `ngx_error_log(NGX_LOG_NOTICE...)` logs it.
          - Logs after, [commit](https://github.com/adamhoof/CDN77-NGINX/commit/9277828e74f99bd6ed3ee0ec8f9f9e921ebee66b)
            - `... XCKF: ngx_http_x_cache_key_filter initialized ...`
            - `... XCKF: Filter called ...`
            - `... XCKF: Next filter returned 0 ...`
            - `... XCKF: Cache context found...`
            - `... XCKF: added header: X-Cache-Key: 6d2ba80804d06a98535b676be52d205f ...`
- Issue: So we checked logs and our module definitely thinks that the header field is added. Why is it not then?
  - Let's check the example [ngx_http_userid_filter_module](https://github.com/nginx/nginx/blob/020b1db7eb187d4a9a5f1d6154c664a463473b36/src/http/modules/ngx_http_userid_filter_module.c) and the [Response -> Header filters](https://nginx.org/en/docs/dev/development_guide.html#http_response) again.
- Fix, [commit](https://github.com/adamhoof/CDN77-NGINX/commit/24678734bddba5dfeac30cb201ae3d8a4560bcd9): OH NOOO it looks like we should not be calling the `ngx_http_next_header_filter` first, but **last** or when we can not continue further!
  - Why? If we called it first, all the other filters (including the final ones that format the response, finalize...) would run BEFORE our header entry is written => the header entry would never be written in time. 
  - This is precisely why we wanted `HTTP_AUX_FILTER` and not just `HTTP_FILTER` in the first place, the `HTTP_AUX_FILTER` makes sure that our filter runs before the final filters. By calling `ngx_http_next_header_filter` we basically erased this advantage.
- Repeat compilation... make another request, WORKS!
  - `HTTP/1.1 200 OK
    Server: nginx/1.26.3
    Date, Content Type, ....
    X-Cache-Key: 6d2ba80804d06a98535b676be52d205f`
- To summarize why this behavior was not achievable by configuration alone, as the task suggests:
  - If we put `add_header X-Cache-Key "$scheme$request_method$host$request_uri"` into `nginx.conf`, it is not the calculated key, it is the **input** that goes into the md5 function, not it's **output**!
  - The calculated key is not exposed as an nginx variable to be used in `nginx.conf`, exists only internally.
##### DOCKER TIME
- Create Dockerfile
  - So now that we know our tests ran successfully on the local environment, let's package it into a docker based env for easy reproducibility.
  - Follow the standard 2-stage pattern for small final image, [commit](https://github.com/adamhoof/CDN77-NGINX/commit/fa0a785ded3b137af2e44c8269f7c0ac8d95517f)
    - Build stage -> Compile nginx with our custom module here. Chosen lightweight Alpine Linux.
    - Runtime stage -> Run the small compiled binary here. Chosen lightweight Alpine Linux.
  - Encountered issues:
    - Issue1: Some dir needed for Nginx did not exist in the Alpine by default.
      - Fix1: Created dirs inside the container.
    - Issue2: Permission issues, avoid root user.
      - Fix2: Create a user with suitable permissions.
    - Issue3: Logging was not visible when checking docker logs (logged into the error and access log files inside logs dir)
      - Fix3: Redirect error log into `/dev/stderr`, access log into `/dev/stdout`, [edited nginx.conf](https://github.com/adamhoof/CDN77-NGINX/commit/eebbdb3ca96d3a036f83732df73d50bc113ae898)
    - Issue4: Logging too verbose to be useful for testing our module
      - Fix4: Filter out only our logs with simple grep filter `docker logs -f nginx-test 2>&1 | grep "XCKF"`
- Test the setup
  - Clone repo
    - `git clone git@github.com:adamhoof/CDN77-NGINX.git`
    - `cd CDN77-NGINX`
  - Build Docker image
    - `docker build -t nginx-xckf:latest .`
  - Run container
    - `docker run -d --name nginx-test -p 8443:8443 nginx-xckf:latest`
  - Follow docker logs
    - `docker logs -f nginx-test 2>&1 | grep "XCKF"`
  - Make test request
    - New terminal window, paste -> `curl -k -I https://localhost:8443/`
  - Expected output
    - In terminal where docker runs, we should see logs from our custom Nginx filter module
      - `... XCKF: "HEAD / HTTP/1.1" 503 "curl/8.9.1" cache_status=HIT`
      - `... XCKF: Filter called;`
      - `... XCKF: Cache context found`
      - `... XCKF: added header: X-Cache-Key: 6d2ba80804d06a98535b676be52d205f`
    - In terminal where request was made, we should see a response header including the appended X-Cache-Key
      - `HTTP/1.1 200 OK
        Server: nginx/1.26.3
        Date, Content Type, ....
        X-Cache-Key: 6d2ba80804d06a98535b676be52d205f`
## 3) - DNS wildcard algorithm
### Task specs and observations
- The purpose of this algorithm is to provide DNS responses for domain names that do not explicitly exist, so like a default, fallback mechanism for a range of potential hostnames.
  - Important rules ([wikipedia](https://en.wikipedia.org/wiki/Wildcard_DNS_record))
    - Wildcard position -> * label must be the leftmost label in the wildcard, that means ONLY `*.y.z`, no `x.*.z`, `x.y.*`,...
    - Scope -> * MUST substitute one or more labels, that means `*.example.com` is ok for both `x.example.com`, `x.y.example.com` and so on, but not `example.com`.
    - DNS zone non-existence -> Wildcard DNS record can only be matched if the requested domain name DOES NOT exist in a DNS zone. (eg. DNS zone `example.com`, holds `ftp.example.com`, request comes in for `ftp.example.com` => can't be applied, explicit records **always take precedence**)
- Example (all rules passed)
  - So we have a wildcard pattern, ie. `*.match.com`
  - Requests come in for www.match.com and www.miss.com.
  - The algorithm needs to figure out whether the request matches any wildcard pattern, in our case `*.match.com`.
  - www.match.com matches, but www.miss.com doesn't.
- Hint points us to [ngx_http_referer_module](https://nginx.org/en/docs/http/ngx_http_referer_module.html), where the algorithm is fully implemented.
  - The algorithm must have time complexity O(1), which I assume the implementation in Nginx will definitely have. Will validate after the analysis.
  - If I had to pick a data structure to implement the algo with, it would probably be some flavor of Trie. 
### Code exploration
- Found [ngx_http_referer_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_referer_module.c), the task hint helped with this.
  - What is a "referer"?
    - An HTTP request header responsible for including the URL of a webpage from which the current request originated.
  - Why referer then, what does it have in common with DNS wildcard record matching?
    - Looking into the [nxg_http_referer_module docs](https://nginx.org/en/docs/http/ngx_http_referer_module.html), now it starts to make sense, we are setting `valid_referers` which are in the form of DNS wildcard records!
    - ie. `valid_referers ...` `... *.example.com` `example.* ...` -> Ok so this specific implementation is using **both leftmost and rightmost** wildcards apparently, good to know.
- Found [valid_referers](https://github.com/nginx/nginx/blob/9785db9bd504ff25c1d84857505e6546fc04ae68/src/http/modules/ngx_http_referer_module.c#L472). from future --> It's purpose is to parse out provided values, validate and place them into their corresponding arrays. <-- from future
- Calls [ngx_hash_keys_array_init](https://github.com/nginx/nginx/blob/9785db9bd504ff25c1d84857505e6546fc04ae68/src/core/ngx_hash.c#L683)
  - Hmmm, it looks like it is initializing 3 arrays? `&ha->keys`, `&ha->dns_wc_head`, `&ha->dns_wc_tail`
    - It seems like those are for exact match, prefix (head) wildcard and postfix (tail) wildcard match, ugh, why?
  - They seem temporary for some reason `... = ngx_pcalloc(ha->temp_pool...)` 
    - from future --> since `valid_referers` directive is valid both in server{} and location{} scopes, it is easier to collect the key strings into temporary arrays first and then merge them into the final structures, just as the `ngx_http_referer_merge_conf` does by calling `ngx_hash_wildcard_init` and `ngx_hash_init`<-- from future
- Right under this function is [ngx_hash_add_key](https://github.com/nginx/nginx/blob/9785db9bd504ff25c1d84857505e6546fc04ae68/src/core/ngx_hash.c#L738).
  - Ahhh this function is actually a pretty good find -> Contains logic for categorizing the key string as either exact match, prefix or suffix wildcard and checks for conflicts.
  - **This file might contain other logic for DNS wildcard matching too.**
- Found [ngx_hash_find](https://github.com/nginx/nginx/blob/9785db9bd504ff25c1d84857505e6546fc04ae68/src/core/ngx_hash.c#L13)
  - This looks for the exact match, NICE!
  - Hmmm that must mean there are separate functions for finding the prefix and suffix wildcards.
- Yes, right under it [ngx_hash_find_wc_head](https://github.com/nginx/nginx/blob/9785db9bd504ff25c1d84857505e6546fc04ae68/src/core/ngx_hash.c#L53) and [ngx_hash_find_wc_tail](https://github.com/nginx/nginx/blob/9785db9bd504ff25c1d84857505e6546fc04ae68/src/core/ngx_hash.c#L147)
- And here is the function [ngx_hash_find_combined](https://github.com/nginx/nginx/blob/9785db9bd504ff25c1d84857505e6546fc04ae68/src/core/ngx_hash.c#L211) that aggregates all of them all, lesgooo!
  1. It first tries to find the exact match (remember the rules, explicit records **always take precedence**) -> `value = ngx_hash_find(&hash->hash, key, name, len);`
  2. Then it checks the prefix wildcard match `value = ngx_hash_find_wc_head(hash->wc_head, name, len);`
  3. And lastly the postfix wildcard match `value = ngx_hash_find_wc_tail(hash->wc_tail, name, len);`
  4. Returns the value if found, NULL if not.
- `ngx_hash_find_combined` leads us back to [ngx_http_referer_variable](https://github.com/nginx/nginx/blob/9785db9bd504ff25c1d84857505e6546fc04ae68/src/http/modules/ngx_http_referer_module.c#L115C1-L115C26) which calls it. It's purpose is to determine if the request's referer header is considered valid according to the `valid_referers`.
- Ok things are getting clearer, now let's just find what data structures are being used to confirm the time complexity for lookups is indeed O(1).
### How does the algorithm work? 
- For that we will analyze these functions:
  - `ngx_hash_init` -> Builds a standard hash table used for exact matches => lookup O(1)
  - `ngx_hash_find` -> 
  - `ngx_hash_wildcard_init` -> Builds specialized, potentially nested hash structures (`ngx_hash_wildcard_t`) for wildcard matches => lookup ?
  - `ngx_hash_find_wc_head / ngx_hash_find_wc_tail` -> 


## Approximate time requirements:
**Research** (topics, terms): 3h <br>
**1) - NGINX cache lookup key analysis**: 10h <br>
**2) - NGINX X-Cache-Key header addition**: 15h <br>
**3) - DNS wildcard algorithm**<br>
**Documentation** (thought process and ideas capture): 13h <br>
