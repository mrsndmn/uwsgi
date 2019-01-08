// https://github.com/tarantool/tarantool/blob/stable/doc/box-protocol.txt
/* async iproto */

#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

// static struct uwsgi_option iproto_options[] = {
//         {"asyncio", required_argument, 0, "a shortcut enabling asyncio loop engine with the specified number of async cores and optimal parameters", uwsgi_opt_setup_asyncio, NULL, UWSGI_OPT_THREADS},
//         {0, 0, 0, 0, 0, 0, 0},
// };

#include "iproto.h"

static int set_req_vars_and_return_ok(struct wsgi_request *wsgi_req) {
	wsgi_req->uh->modifier1 = 5; // psgi modif // todo move to config
	wsgi_req->uh->modifier2 = 0; // todo make it custom
	wsgi_req->parsed = 1;

	// UWSGI_SCHEME
	// todo not scheme but proto or both
	// wsgi_req->scheme = "iproto";
	// wsgi_req->scheme_len = 6;

// #ifdef UWSGI_DEBUG
	struct iproto_header *ih = (struct iproto_header *) wsgi_req->buffer;
	uwsgi_log("sdvfsdgfDGDF!!!!!In parse iproto! %s\n\n", wsgi_req->scheme);
	uwsgi_log("sdvfsdgfDGDF!!!!!In parse iproto! type %d\n\n", ih->type);
	uwsgi_log("sdvfsdgfDGDF!!!!!In parse iproto! request_id %d\n\n", ih->request_id);
	uwsgi_log("iproto req body_length = %d\n", ih->body_length);
	uwsgi_log("iproto req body = %X\n", wsgi_req->buffer + ih_len);
// #endif


	return UWSGI_OK;
}

static int uwsgi_proto_iproto_parser(struct wsgi_request *wsgi_req) {
	uwsgi_log("In parse iproto!\n\n");

	char *ptr = (char *) wsgi_req->buffer;
	// что будет, если тут считаем больше, чем размер хидера?
	ssize_t len = read(wsgi_req->fd, ptr + wsgi_req->proto_parser_pos, (uwsgi.buffer_size + ih_len) - wsgi_req->proto_parser_pos);
	if (len > 0) {
		wsgi_req->proto_parser_pos += len;
		if (wsgi_req->proto_parser_pos >= ih_len) {
			struct iproto_header *ih = (struct iproto_header *) wsgi_req->buffer;
			wsgi_req->len = ih->body_length + ih_len;
			uwsgi_log("In parse iproto: req_len = %d; ppos = %d\n", wsgi_req->len, wsgi_req->proto_parser_pos);
			if (wsgi_req->proto_parser_pos == wsgi_req->len) {
				return set_req_vars_and_return_ok(wsgi_req);
			}
			if (wsgi_req->proto_parser_pos > wsgi_req->len) {
				wsgi_req->proto_parser_remains     = wsgi_req->proto_parser_pos - wsgi_req->len;
				wsgi_req->proto_parser_remains_buf = wsgi_req->buffer + wsgi_req->len;
				return set_req_vars_and_return_ok(wsgi_req);
			}
			if (wsgi_req->len > uwsgi.buffer_size) {
				uwsgi_log("iproto: invalid request block size: %u (max %u)...skip\n", wsgi_req->len, uwsgi.buffer_size);
				return -1;
			}
		}
		return UWSGI_AGAIN;
	}
	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
			return UWSGI_AGAIN;
		}
		uwsgi_error("uwsgi_proto_uwsgi_parser()");
		return -1;
	}
	// 0 len
	if (wsgi_req->proto_parser_pos > 0) {
		uwsgi_error("uwsgi_proto_uwsgi_parser()");
	}
	return -1;
}

void uwsgi_proto_iproto_setup(struct uwsgi_socket *uwsgi_sock) {
	uwsgi_sock->proto = uwsgi_proto_iproto_parser;
	uwsgi_sock->proto_accept = uwsgi_proto_base_accept;
	uwsgi_sock->proto_prepare_headers = uwsgi_proto_base_prepare_headers;
	uwsgi_sock->proto_add_header = uwsgi_proto_base_add_header;
	uwsgi_sock->proto_fix_headers = uwsgi_proto_base_fix_headers;
	uwsgi_sock->proto_read_body = uwsgi_proto_base_read_body;
	uwsgi_sock->proto_write = uwsgi_proto_base_write;
	uwsgi_sock->proto_writev = uwsgi_proto_base_writev;
	uwsgi_sock->proto_write_headers = uwsgi_proto_base_write;
	uwsgi_sock->proto_sendfile = uwsgi_proto_base_sendfile;
	uwsgi_sock->proto_close = uwsgi_proto_base_close;
	if (uwsgi.offload_threads > 0)
		uwsgi_sock->can_offload = 1;
}

static void iproto_register_proto() {
#ifdef UWSGI_DEBUG
	uwsgi_log("ifdef In register iproto!\n\n");
#endif
	uwsgi_log("In register iproto!\n\n");
	uwsgi_register_protocol("iproto", uwsgi_proto_iproto_setup);
}



struct uwsgi_plugin iproto_plugin = {
	.name = "iproto",
	// .options = iproto_options,
	// .request = 
	.on_load = iproto_register_proto,
	// .init = http_init,
	// .on_load = http_setup,
};