cmake_minimum_required(VERSION 3.30)
project(ngx_http_x_cache_key_filter_module C)
set(CMAKE_C_STANDARD 11)
set(NGINX_SRC_DIR "/home/adamhoof/Projects/nginx-1.26.3")

include_directories(
        "${NGINX_SRC_DIR}/src/core"
        "${NGINX_SRC_DIR}/src/event"
        "${NGINX_SRC_DIR}/src/event/modules"
        "${NGINX_SRC_DIR}/src/os/unix"
        "${NGINX_SRC_DIR}/src/http"
        "${NGINX_SRC_DIR}/src/http/modules"
        "${NGINX_SRC_DIR}/objs"
)

add_library(ngx_http_x_cache_key_filter_module STATIC
        ngx_http_x_cache_key_filter_module.c
)

target_compile_definitions(ngx_http_x_cache_key_filter_module PRIVATE NGX_HTTP_CACHE=1)
