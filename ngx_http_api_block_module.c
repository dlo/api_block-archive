
/*
 * Copyright (C) Dan Loewenherz
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <string.h>
#include <stdlib.h>
#include <libmemcached/memcached.h>

#define NGX_HTTP_BLOCK_ON 1
#define NGX_HTTP_BLOCK_OFF 0

static void *ngx_http_api_block_create_conf(ngx_conf_t *cf);
static char *ngx_http_api_block_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_api_block_init(ngx_conf_t *cf);
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

typedef struct {
		ngx_flag_t enabled;
} ngx_http_api_block_conf_t;

static ngx_command_t ngx_http_api_block_commands[] = {
    {
			ngx_string("api_block"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_api_block_conf_t, enabled),
      NULL
		},

		ngx_null_command
};

static ngx_http_module_t ngx_http_api_block_module_ctx = {
	NULL,                                  /* preconfiguration */
	ngx_http_api_block_init,							 /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_http_api_block_create_conf,     /* create location configuration */
	ngx_http_api_block_merge_conf       /* merge location configuration */
};

ngx_module_t  ngx_http_api_block_module = {
    NGX_MODULE_V1,
    &ngx_http_api_block_module_ctx,      /* module context */
    ngx_http_api_block_commands,              /* module directives */
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

static ngx_int_t
ngx_http_api_block_header_filter(ngx_http_request_t *r) {
	return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_api_block_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
	ngx_chain_t *chain_link;
	int chain_contains_last_buffer = 0;
	for ( chain_link = in; chain_link != NULL; chain_link = chain_link->next ) {
		if (chain_link->buf->last_buf)
			chain_contains_last_buffer = 1;
	}

	if (!chain_contains_last_buffer) {
		return ngx_http_next_body_filter(r, in);
	}

	ngx_buf_t *b;
	b = ngx_calloc_buf(r->pool);
	if (b == NULL) {
		return NGX_ERROR;
	}

	b->pos = (u_char *) "<!-- served -->";
	b->last = b->pos + sizeof("<!-- served -->") - 1;

	ngx_chain_t added_link;
	added_link.buf = b;
	added_link.next = NULL;

	chain_link->next = added_link;
	chain_link->buf->last_buf = 0;
	added_link->buf->last_buf = 1;

	return ngx_http_next_body_filter(r, in);

		char *remote_addr_val, *value, *servername, *result;
		size_t remote_addr_len, len;
		uint32_t flags;
		int i;
		ngx_http_api_block_conf_t *conf;

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "block filter");

    conf = ngx_http_get_module_loc_conf(r, ngx_http_api_block_module);

		// Check if the filter has been enabled
		if (!conf->enabled == NGX_HTTP_BLOCK_ON) {
			return ngx_http_next_body_filter(r, in);
		}

		remote_addr_val = (char *)r->connection->addr_text.data;
		remote_addr_len = sizeof(remote_addr_val) + 1;

		memcached_return mc_error;
		memcached_return_t rc_m;
		memcached_server_st *servers;
		memcached_st *ab_memcache = memcached_create(NULL);
		servername = "127.0.0.1";

		servers = memcached_server_list_append(NULL, servername, 11211, &rc_m);
		memcached_server_push(ab_memcache, servers);

		result = memcached_get(ab_memcache, remote_addr_val, remote_addr_len, &len,
				&flags, &mc_error);
		if (result) {
			i = atoi(result) << 1;
			value = (char *)malloc(sizeof(char) * 16);
			sprintf(value, "%d", i);
			rc_m = memcached_set(ab_memcache, remote_addr_val, remote_addr_len, 
					value, sizeof(value), (time_t)i, (uint32_t)0);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		else {
			rc_m = memcached_set(ab_memcache, remote_addr_val, remote_addr_len, 
					"1", sizeof("1"), (time_t)1, (uint32_t)0);
		}

		memcached_server_free(servers);
		memcached_free(ab_memcache);

		return ngx_http_next_body_filter(r, in);
}

static void *
ngx_http_api_block_create_conf(ngx_conf_t *cf) {
    ngx_http_api_block_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_api_block_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    return conf;
}

static char *
ngx_http_api_block_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_api_block_conf_t *prev = parent;
    ngx_http_api_block_conf_t *conf = child;

    if (conf->enabled == NGX_CONF_UNSET) {
			conf->enabled = NGX_HTTP_BLOCK_OFF;
    }

    ngx_conf_merge_value(conf->enabled, prev->enabled, NGX_HTTP_BLOCK_OFF);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_api_block_init(ngx_conf_t *cf) {
		// ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "hi there");

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_api_block_header_filter;

		ngx_http_next_body_filter = ngx_http_top_body_filter;
		ngx_http_top_body_filter = ngx_http_api_block_body_filter;

		return NGX_OK;
}

