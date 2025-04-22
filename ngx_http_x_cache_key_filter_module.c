#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_x_cache_key_filter_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_x_cache_key_header_filter(ngx_http_request_t *r);

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

/* Module context definition */
static ngx_http_module_t  ngx_http_x_cache_key_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_x_cache_key_filter_init,      /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


/* Module definition */
ngx_module_t  ngx_http_x_cache_key_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_x_cache_key_filter_module_ctx, /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
 * Post-configuration initialization function.
 * Injects header filter into the filter chain.
 */
static ngx_int_t
ngx_http_x_cache_key_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_x_cache_key_header_filter;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                   "XCKF: ngx_http_x_cache_key_filter initialized");

    return NGX_OK;
}

/*
 * The actual header filter function.
 * Adds X-Cache-Key header if the cache key was calculated for the request.
 */
static ngx_int_t
ngx_http_x_cache_key_header_filter(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "XCKF: Filter called");
    ngx_http_cache_t  *c;
    ngx_str_t          hex_key_ngx_str;
    ngx_table_elt_t   *h;
    ngx_uint_t         hex_key_str_len = 32;

    // Operate only on the main request
    if (r != r->main) {
        ngx_http_next_header_filter(r);
    }

    // Do we have a cache context?
    c = r->cache;
    if (c == NULL) {
        return ngx_http_next_header_filter(r);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "XCKF: Cache context found");

    // Allocate memory for the key string
    hex_key_ngx_str.data = ngx_pnalloc(r->pool, hex_key_str_len);
    if (hex_key_ngx_str.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "XCKF: failed to allocate memory for X-Cache-Key value");
        return NGX_ERROR;
    }

    // Convert the 16-byte binary key to a 32-byte hex string
    ngx_hex_dump(hex_key_ngx_str.data, c->key, NGX_HTTP_CACHE_KEY_LEN);
    hex_key_ngx_str.len = hex_key_str_len;

    // Add the X-Cache-Key header
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    // Set header fields
    h->hash = 1;
    ngx_str_set(&h->key, "X-Cache-Key");
    h->value = hex_key_ngx_str;



    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "XCKF: added header: X-Cache-Key: %V", &h->value);

    return ngx_http_next_header_filter(r);
}
