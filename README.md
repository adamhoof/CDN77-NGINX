# NGINX task

## Research

NGINX -> high performance, opensource software efficient under heavy load, event driven arch, can function as a web server, reverse proxy with load balancer, cache etc. -> those are configurable<br>
Forward vs Reverse proxy -> acts on behalf of the client, eg. VPN that hides client IP vs acts on behalf of the server, eg. reverse proxy with load balancing, caching etc. <br>
**Configuration** <br>
- Defined in a nginx.conf
- Scopes/Context: by default everything is in a "main" scope/context, where all general settings are configured. We put other scopes and directives/commands inside.
- Directives/Commands: basically specific settings with arguments, eg. how many connections per worker can we have, http routing config, cache, ...
- This approach of scopes and commands seems to provide a really good configuration granularity.

**Development guide most important parts** <br>
- Architecture goes like this: Small core + pluggable modules. 
- Uses its own memory allocation method
  - Allocate larger chunk (pool) of memory first.
  - Use ngx_palloc(pool, size) to request memory from this pre-allocated space. SPEED!
  - The deletion is also "automated", since the pool has the ownership over the memory! 
- Has its own data types -> ngx_str_t, ngx_uint_t, uintptr_t, ngx_array_t, ngx_list_t... cool!
- Directives/commands are defined using ngx_command_t, specifying name, args, allowed contexts, handler function of a single directive.
  - Allowed contexts examples: NGX_MAIN_CONF (top level), NGX_HTTP_MAIN_CONF (http block), NXG_HTTP_SRV_CONF (http -> server block)
- Contexts in code are represented like this ie. ngx_http_<module>_main_conf_t ("top level" of http), ngx_http_<module>_srv_conf_t (http -> server), ngx_http_proxy_srv_conf_t (http -> server inside proxy module)

## 1) - NGINX cache lookup key analysis

### Thought process (literary):

1. Figure out where to even look in the docs, the task is about cache, let's search cache.
    - Ok there is a couple of cache related things, we are specifically interested in how cache key works in there, co perhaps proxy_cache_key link might be correct.
    - So this is only an overview of how to configure things -> nginx is opensource, look into the code.
2. Code exploration
    - ngx_http_proxy_module.c looks legit, search cache keyword, found ngx_http_proxy_cache_key function.
    - A bunch of mumbo jumbo here, looks like the function takes in some config and parses it into internal complex compiled value.
    - We gotta go back and dig a little bit more into how nginx works under the hood in general. (jump into [Research -> Development guide most important parts](#research) 
      - So from what we know, core concepts are scopes and commands. How do they map into code?
        - The scope hierarchy of scopes is important. We will probably care the most about http. If we used http in conf, then the code allocates structs ngx_http_<module_name>_main_conf_t.
        - Inside the http, we can define other scopes like server. Again if we did that, the code allocates ngx_http_<module_name>_srv_conf_t.

## 2) - NGINX X-Cache-Key header addition
## 3) - Bonus Lua module API extension

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
