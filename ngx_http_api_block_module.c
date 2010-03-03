
/*
 * Copyright (C) Dan Loewenherz
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <string.h>
#include <libmemcached/memcached.h>

typedef struct {
    ngx_uint_t  methods;
    ngx_uint_t  access;
    ngx_uint_t  min_delete_depth;
    ngx_flag_t  create_full_put_path;
} ngx_http_dav_loc_conf_t;

static char *ngx_http_api_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_api_block_commands[] = {
    {
			ngx_string("api_block"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_api_block,
      0,
      0,
      NULL
		},

		ngx_null_command
};

static ngx_http_module_t ngx_http_api_block_module_ctx = {
	NULL,                                  /* preconfiguration */
	NULL,                                  /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	NULL,                                  /* create location configuration */
	NULL                                   /* merge location configuration */
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

static ngx_int_t ngx_http_api_block_handler(ngx_http_request_t *r) {
    size_t             size;
    ngx_int_t          rc;
    ngx_buf_t         *b;
    ngx_chain_t        out;
		char							*remote_addr_val;
		size_t						 remote_addr_len;

		memcached_return_t rc_m;
		memcached_server_st *servers;
		memcached_st *memc = memcached_create(NULL);
		char servername[] = "127.0.0.1";

		remote_addr_val = (char *)r->connection->addr_text.data;
		remote_addr_len = sizeof(remote_addr_val) + 1;

		servers = memcached_server_list_append(NULL, servername, 11211, &rc_m);

		memcached_server_push(memc, servers);

		char *value = "test";
		size_t value_length = strlen(value);

		rc_m = memcached_set(memc, remote_addr_val, remote_addr_len, value, value_length,
				(time_t)0, (uint32_t)0);

		memcached_server_free(servers);
		memcached_free(memc);

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *) "text/plain";

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

		size = sizeof(r->connection->addr_text.data) + sizeof("\n\0");

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

		b->last = ngx_sprintf(b->last, "%s\n", r->connection->addr_text.data);

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

		b->memory = 1;
    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static char *ngx_http_api_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_api_block_handler;

    return NGX_CONF_OK;
}

