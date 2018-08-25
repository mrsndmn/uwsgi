// https://github.com/tarantool/tarantool/blob/stable/doc/box-protocol.txt
/* async iproto */

#include <uwsgi.h>



// static struct uwsgi_option iproto_options[] = {
//         {"asyncio", required_argument, 0, "a shortcut enabling asyncio loop engine with the specified number of async cores and optimal parameters", uwsgi_opt_setup_asyncio, NULL, UWSGI_OPT_THREADS},
//         {0, 0, 0, 0, 0, 0, 0},
// };

// todo move to uwsgi_req
struct __attribute__ ((packed)) iproto_header {
	uint32_t type;
	uint32_t body_length;
	uint32_t request_id;
};

extern struct uwsgi_server uwsgi;
const size_t ih_len = sizeof(struct iproto_header); // iproto headers length = 24 bytes
struct iproto_header *ih;
char *ptr = (char *) ih;

static int uwsgi_proto_iproto_parser(struct wsgi_request *wsgi_req) {
	// struct iproto_header *ih;
    // что будет, если тут считаем больше, чем размер хидера?
	ssize_t len = read(wsgi_req->fd, ptr + wsgi_req->proto_parser_pos, (uwsgi.buffer_size + ih_len) - wsgi_req->proto_parser_pos);
	if (len > 0) {
		wsgi_req->proto_parser_pos += len;
		if (wsgi_req->proto_parser_pos >= ih_len) {
			wsgi_req->len = wsgi_req->uh->_pktsize;
			if ((wsgi_req->proto_parser_pos - ih_len) == wsgi_req->uh->_pktsize) {
				return UWSGI_OK;
			}
			if ((wsgi_req->proto_parser_pos - ih_len) > wsgi_req->uh->_pktsize) {
				wsgi_req->proto_parser_remains = wsgi_req->proto_parser_pos - (ih_len + wsgi_req->uh->_pktsize);
				wsgi_req->proto_parser_remains_buf = wsgi_req->buffer + wsgi_req->uh->_pktsize;
				return UWSGI_OK;
			}
			if (wsgi_req->uh->_pktsize > uwsgi.buffer_size) {
				uwsgi_log("invalid request block size: %u (max %u)...skip\n", wsgi_req->uh->_pktsize, uwsgi.buffer_size);
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
    // uwsgi_log("In register iproto!\n\n");
    uwsgi_register_protocol("iproto", uwsgi_proto_iproto_setup);
}



struct uwsgi_plugin iproto_plugin = {
	.name = "iproto",
	// .options = iproto_options,
    // .request = 
	.on_load = iproto_register_proto,
};