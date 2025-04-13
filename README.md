# NGINX task

## Research

NGINX -> high performance, opensource software efficient under heavy load, event driven arch, can function as a web server, reverse proxy with load balancer, cache etc. -> CONFIGURABLE<br>
Forward vs Reverse proxy -> acts on behalf of the client, eg. VPN that hides client IP vs acts on behalf of the server, eg. reverse proxy with load balancing, caching etc. <br>
#### Configuration
- Defined in a nginx.conf
- Scopes/Context: by default everything is in a "main" scope/context, where all general settings are configured. We put other scopes and directives/commands inside.
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
    - Ok there is a couple of cache related things, we are specifically interested in how cache key works in there, so perhaps proxy_cache_key link might be correct.
    - So this is only an overview of how to configure things -> nginx is opensource, look into the code.
2. Code exploration
    - ngx_http_proxy_module.c looks legit, search cache keyword, found ngx_http_proxy_cache_key function.
    - A bunch of mumbo jumbo here, looks like the function takes in some config and parses it into internal complex compiled value. from future --> this is responsible for creating the **parsed** "key template" from proxy_cache_key directive for later use (request comes, evaluate out it's variables based on this "key template", build the final keys string, which is then hashed) <-- from future
      - We gotta go back and dig a little bit more into how nginx works under the hood in general before proceeding. (added to [Development guide most important parts](#development-guide-most-important-parts)) <br>
    - **QUESTIONS 1 + 2: Podle jakého klíče nginx v cache vyhledává + jak se tento klíč vypočítává?** <br>
      - What can the cache even look for? -> Generally speaking some response from server, in this case HTTP response.
      - Issue: Storing big responses in RAM would not be ideal, deplete memory pretty fast. Storing it on a disk and looking up there would be slow.
      - Solution:
        - Responses must go on a disk to not deplete RAM. For fast lookups, we will store the key (or more metadata) in a RAM.
        - Because of those facts, we will need to search some interaction between the cache and filesystem (everything is a file, said Tux), since the response will be stored on a disk and we need to calculate a key representing the presence of this response.
      - Found ngx_http_file_cache.c file -> [void ngx_http_file_cache_create_key(ngx_http_request_t *r)](https://github.com/nginx/nginx/blob/b6e7eb0f5792d7a52d2675ee3906e502d63c48e3/src/http/ngx_http_file_cache.c#L228)
        - Here we can see that ngx_http_cache_t pointer is stored in the request "c = r->cache;", which holds cache related information for this specific request (ie. GET /image.png).
        - The crc32 and md5 are initialized for checksum (error detection) and hashing purposes ngx_crc32_init(c->crc32); ngx_md5_init(&md5);
        - Iterate over the key components ( apply func md5(unique key components) -> unique, deterministic output hash ) stored in c->keys, print each for debugging purposes, update crc32 and md5 calculation with this current key component. The keys are the taken from proxy_cache_key, which defaults to `$scheme$proxy_host$request_uri` but can be changed.
        - Calculate offset to house the nginx internal header containing metadata to distinguish it from the original response headers.
        - Finalize the crc32 and md5 calculation. Important for us here is the md5 calculation, which stores the result into c->key as we can see in the ngx_md5.c -> [void ngx_md5_final(u_char result[16], ngx_md5_t *ctx)](https://github.com/nginx/nginx/blob/master/src/core/ngx_md5.c#L62)
        - Now c->cache holds the key (calculated unique, deterministic hash)!
    - **QUESTION 3: K čemu se používá?**
        - In Qs 1 + 2 we found out how this key is calculated and that it is used for cache lookup.
        - But the hint in the task description tells us "jméno souboru v cache", which is a strong indicator of the key either being the full filename or part of it.
        - I'm wondering, where is this whole caching process or atleast part of it located in the codebase? Inside the ngx_http_file_cache.c are individual module functions, but it needs to be called from somewhere. Might actually lead us to the part where it writes the key as a filename or part of it, as the hint points us.
          - Digging where else _ngx_http_file_cache_create_key(ngx_http_request_t *r)_ is used, found ngx_http_upstream.c -> [ngx_http_upstream_cache(ngx_http_request_t *r, ngx_http_upstream_t *u)](https://github.com/nginx/nginx/blob/b6e7eb0f5792d7a52d2675ee3906e502d63c48e3/src/http/ngx_http_upstream.c#L882).
          - Inside, this caught my eye [ngx_int_t ngx_http_file_cache_open(ngx_http_request_t *r)](https://github.com/nginx/nginx/blob/b6e7eb0f5792d7a52d2675ee3906e502d63c48e3/src/http/ngx_http_file_cache.c#L265), leads back to the http_file_cache.c aight :D
          - But looking through, it seems we hit it! It calls [static ngx_int_t ngx_http_file_cache_name(ngx_http_request_t *r, ngx_path_t *path)](https://github.com/nginx/nginx/blob/b6e7eb0f5792d7a52d2675ee3906e502d63c48e3/src/http/ngx_http_file_cache.c#L994), where the filename generation happens! 
            - It checks if the cache already has the name generated by doing: _if (c->file.name.len)_
            - Calculates the required length for the full cache path string: _c->file.name.len = path->name.len + 1 + path->len + 2 * NGX_HTTP_CACHE_KEY_LEN;_
            - Allocate memory from pool to buffer based on this path string (don't forget to protecc ma boi null terminator): _c->file.name.data = ngx_pnalloc(r->pool, c->file.name.len + 1);_
            - Copy base cache dir path into the buffer: _ngx_memcpy(c->file.name.data, path->name.data, path->name.len);_
            - **Convert the c->key to 32 char HEX string:** _representation p = ngx_hex_dump(p, c->key, NGX_HTTP_CACHE_KEY_LEN);_
      - **QUESTION 4: Jaká je jeho lokace z hlediska datových struktur?**
      - **QUESTION 5: Jaká je jeho lokace z hlediska paměťového umístění (dle OS)**

## 2) - NGINX X-Cache-Key header addition
## 3) - DNS wildcard algorithm
## 4) - Bonus Lua module API extension

# High level questions to answer

Why did we choose to solve it this way?<br>
What did we get stuck at, how did we overcome it? How could it be solved differently? -> Started with almost no knowledge of some terms, learnt it <br>
How would the solution scale?<br>
Performance, code maintainability, security...<br>
What parts of the solution are optimal, which are not?<br>
What could be improved and why not improve it straight up?<br>
How long did the task take? (research, implementation, debug)<br>
How did we think about the task?<br>
What did we come up with and what did we threw away?<br>
What would we do if it went to production? -> Proper testing has already taken place on a pre-prod environemnt<br>
