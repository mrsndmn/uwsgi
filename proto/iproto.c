/* async iproto protocol parser */

#include "cbor.h"
#include <uwsgi.h>

// todo do not close iproto connection! use request_id to map the requests

struct __attribute__ ((packed)) iproto_header {
	int32_t type;
	int32_t body_length;
	int32_t request_id;
};

const size_t ih_len = sizeof(struct iproto_header); // iproto headers length = 12 bytes

extern struct uwsgi_server uwsgi;

char* iproto_type2_method(int32_t type){
	switch (type)
	{
		case 1   : return "GET";
		case 2   : return "HEAD";
		case 4   : return "POST";
		case 8   : return "PUT";
		case 16  : return "DELETE";
		case 32  : return "CONNECT";
		case 64  : return "OPTIONS";
		case 128 : return "TRACE";
		case 256 : return "PATCH";
		default:
			return "";
	}
}

static int uwsgi_proto_iproto_parser(struct wsgi_request *wsgi_req) {
	uwsgi_log("In parse iproto! ppos %d\n\n", wsgi_req->proto_parser_pos);

	if (!wsgi_req->proto_parser_buf) {
		wsgi_req->proto_parser_buf = uwsgi_malloc(uwsgi.buffer_size);
		wsgi_req->proto_parser_buf_size = uwsgi.buffer_size;
	}

	if(!wsgi_req->protocol) {
		wsgi_req->protocol = "iproto";
		wsgi_req->protocol_len = 6;
	}

	char *ptr = wsgi_req->proto_parser_buf;

	ssize_t len = read(wsgi_req->fd, ptr + wsgi_req->proto_parser_pos, uwsgi.buffer_size - wsgi_req->proto_parser_pos);
	size_t req_len = ih_len; // firstly read the headers

	// reading headers and body
	if (len > 0) {
		if(uwsgi.buffer_size <= wsgi_req->proto_parser_pos + len) {
			uwsgi_log("iproto: invalid request block size! request is too big %u (max %u)...skip\n", wsgi_req->proto_parser_pos + len, uwsgi.buffer_size);
			return -1;
		}
		wsgi_req->proto_parser_pos += len;
		if (wsgi_req->proto_parser_pos >= req_len) {
			if(req_len == ih_len) {
				struct iproto_header *ih = (struct iproto_header *) wsgi_req->proto_parser_buf;
				uwsgi_log("In parse iproto: ih_len = %d, type = %d, body_len = %d, req_id = %d \n", ih_len, ih->type, ih->body_length, ih->request_id);

				char *tmp = uwsgi_num2str(ih->type); // tmp is 11 bytes length buffer
				wsgi_req->len += proto_base_add_uwsgi_var(wsgi_req, "IPROTO_TYPE",        11, tmp, strlen(tmp));

				char *req_meth = iproto_type2_method(ih->type);
				wsgi_req->len += proto_base_add_uwsgi_var(wsgi_req, "REQUEST_METHOD",     14, req_meth, strlen(req_meth));

				uwsgi_num2str2(ih->request_id, tmp);
				wsgi_req->len += proto_base_add_uwsgi_var(wsgi_req, "IPROTO_REQUEST_ID",  17, tmp, strlen(tmp));

				uwsgi_num2str2(ih->body_length, tmp);
				wsgi_req->len += proto_base_add_uwsgi_var(wsgi_req, "IPROTO_BODY_LENGTH", 18, tmp, strlen(tmp));
				free(tmp);

				req_len += ih->body_length;
			}

			if (wsgi_req->proto_parser_pos > req_len) {
				// wsgi_req->proto_parser_remains     = wsgi_req->proto_parser_pos - ih_len;
				// wsgi_req->proto_parser_remains_buf = wsgi_req->buffer + ih_len;
				uwsgi_log("Invalid iproto body_length!\n");
				return -1;
			}

			// parsing body
			if (wsgi_req->proto_parser_pos == req_len) {
				struct iproto_header *ih = (struct iproto_header *) wsgi_req->proto_parser_buf;

				struct cbor_load_result result;
				cbor_item_t* iproto_body = cbor_load(wsgi_req->proto_parser_buf + ih_len, ih->body_length, &result);

				if (result.error.code != CBOR_ERR_NONE) {
					uwsgi_log( "There was an error while reading the input near byte %zu (read %zu bytes in total): ", result.error.position, result.read);
					switch (result.error.code) {
					case CBOR_ERR_MALFORMATED:		{ uwsgi_log("Malformed data\n"); break; }
					case CBOR_ERR_MEMERROR:			{ uwsgi_log("Memory error -- perhaps the input is too large?\n"); break; }
					case CBOR_ERR_NODATA:			{ uwsgi_log("The input is empty\n"); break; }
					case CBOR_ERR_NOTENOUGHDATA:	{ uwsgi_log("Data seem to be missing -- is the input complete?\n"); break; }
					case CBOR_ERR_SYNTAXERROR:		{ uwsgi_log( "Syntactically malformed data -- see http://tools.ietf.org/html/rfc7049\n"); break; }
					case CBOR_ERR_NONE:				{ break; }
					}
					return -1;
				}

				if(!cbor_isa_array(iproto_body) || cbor_array_size(iproto_body) != 2) {
// todo remove gotos
cbor_err:
					cbor_decref(&iproto_body); // todo подумать надо структурой. Может быть плохо с параметрами, которые должны быть отмортированы, если порядок параметров важен...
					uwsgi_log("iproto: body muust be type of cbor array: [ '/path/', { param1 => value1, param2 => value2 ... } ]!\n");
					return -1;
				}
				uwsgi_log("cbor array is ok\n");

				cbor_item_t* path = cbor_array_get(iproto_body, 0);
				if(!cbor_isa_bytestring(path)) {
					uwsgi_log("iproto: cbor: invalid path\n");
					cbor_decref(&path);
					goto cbor_err;
				}

				// todo check here is nothing awful
				char* path_ptr = (char *) cbor_bytestring_handle(path);
				wsgi_req->len += proto_base_add_uwsgi_var(wsgi_req, "PATH_INFO", 9, path_ptr, cbor_bytestring_length(path));
				uwsgi_log("cbor path is %s\n", path_ptr);

				cbor_item_t* params = cbor_array_get(iproto_body, 1);
				if(!cbor_isa_map(params)) {
					uwsgi_log("iproto: cbor: invalid params\n");
cbor_param_err:
					cbor_decref(&params);
					goto cbor_err;
				}
				uwsgi_log("cbor handling params\n");
				struct cbor_pair *handle = cbor_map_handle(params);

				wsgi_req->len += proto_base_add_uwsgi_var(wsgi_req, "REQUEST_URI", 11, path_ptr, cbor_bytestring_length(path));

				if(cbor_map_size(params) > 0) {
					size_t i;
					uint16_t klen = 0, vlen = 0, j = 0;
					char* kp = NULL, *vp = NULL;
					char *buffer = wsgi_req->buffer + wsgi_req->len;// todo add uwsgi var and params chunk by chunk!
					char *fix_req_uri_length_ptr = buffer - cbor_bytestring_length(path) - 2;

					memcpy(buffer, "?", 1);
					buffer++;
					uint16_t query_str_len = 1;

					for (i=0; i < cbor_map_size(params); i++) {
						if(!cbor_isa_bytestring(handle[i].key) || ! cbor_isa_bytestring(handle[i].value)){
							uwsgi_log("iproto: cbor: params map keys and values must be byte string\n");

							cbor_decref(&params);
							goto cbor_param_err;
						}


						kp = (char *) cbor_bytestring_handle(handle[i].key);
						vp = (char *) cbor_bytestring_handle(handle[i].value);

						klen = cbor_bytestring_length(handle[i].key);
						vlen = cbor_bytestring_length(handle[i].value);
						uwsgi_log("key %d %.*s, value %d %.*s\n", klen, klen, kp, vlen, vlen, vp);

						// keys cant be encoded
						for(j = 0; j < klen; j++) {
							if(check_byte_need_url_encode(*(kp + j))) {
								uwsgi_log("iproto: cbor: params keys keys cant be url encoded!\n");
								goto cbor_param_err;
							}
						}

						// here we have to urlencode params values. Thus vlen could increase(maximum length may increase by 3 times).
						// If it will not increas as much that we cant write to buffer we will write rihgt there.
						// Else fallback to writing it by chunk..
						// 2 + 2 bytes for lengths
						//                                                     '&'   key  '='  param
						uint16_t probable_len = wsgi_req->len + query_str_len + 1 + klen + 1 + vlen; // min length
						uwsgi_log("cur_len = %d, probable_len = %d\n", wsgi_req->len, probable_len);
						// max length
						if(probable_len + 2*vlen <= uwsgi.buffer_size) {
add_encoded_param:
							if(i > 0) {
								memcpy(buffer, "&", 1);
								buffer++;
							}
							buffer += unsafe_add_uwsgi_var_chunk(buffer, kp, klen);

							memcpy(buffer, "=", 1);
							buffer++; query_str_len++;

							http_url_encode(vp, &vlen, buffer);	// writing encoded param to buffer

							uwsgi_log("klen = %d, vlen = %d\n", klen, vlen);
							query_str_len += 1 + klen  + 1 + vlen;
						}
						else if (probable_len > uwsgi.buffer_size) { // no chance to write it to uwsgi buffer
							goto cbor_param_err;
						}
						else {// will compute real encoded length
							for(j = 0; j < vlen; j++) {
								if(check_byte_need_url_encode(*(vp + j))) {
									probable_len += 2;
									if(probable_len > uwsgi.buffer_size)
										goto cbor_param_err;
								}
							}

							goto add_encoded_param;
						}
					}
					unsafe_add_uwsgi_var_chunk_length(fix_req_uri_length_ptr, cbor_bytestring_length(path) + query_str_len);
					wsgi_req->len += query_str_len;
					wsgi_req->len += proto_base_add_uwsgi_var(wsgi_req, "QUERY_STRING", 12, fix_req_uri_length_ptr + 2 + cbor_bytestring_length(path) + 1, query_str_len - 1);
				}

				uwsgi_log("cur_len = %d\n", wsgi_req->len);
				uwsgi_log("Cbor is ok\n");
				cbor_decref(&iproto_body);

				return UWSGI_OK;
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


struct uwsgi_buffer *uwsgi_proto_iproto_prepare_headers(struct wsgi_request *wsgi_req, char *s, uint16_t sl) {
	uwsgi_log("uwsgi_proto_iproto_prepare_headers(): %d\n", wsgi_req->status);
	struct uwsgi_buffer *ub = uwsgi_buffer_new( ih_len + 4 ); // <response> ::= <header><return_code>{<response_body>}
	// just cpoying headers from request but dont foreget to update response_body
	struct iproto_header *ih = (struct iproto_header *) wsgi_req->proto_parser_buf;
	ih->body_length = 0;
	if (uwsgi_buffer_append(ub, (char*)ih, ih_len)) 	goto end;
	if (uwsgi_buffer_append(ub, (char*)&(wsgi_req->status), 4)) goto end;
	return ub;
end:
		uwsgi_buffer_destroy(ub);
		return NULL;
}

struct uwsgi_buffer *uwsgi_proto_iproto_add_header(struct wsgi_request *wsgi_req, char *k, uint16_t kl, char *v, uint16_t vl) {
	uwsgi_log("uwsgi_proto_iproto_add_header(): kl = %d, vl = %d value %.*s\n", kl, vl, vl, v);

	if(!uwsgi_strnicmp(k, kl, "Content-Length", 14)) {
		struct iproto_header *ih = (struct iproto_header *) wsgi_req->headers->buf;

		int body_length = uwsgi_str_num(v, vl);
		ih->body_length = body_length;
		uwsgi_log("current body length %d\n", ih->body_length);

		// wsgi_req->headers = (struct uwsgi_buffer *) ih;
	}
	return uwsgi_buffer_new(0);
}

int uwsgi_proto_iproto_fix_headers(struct wsgi_request * wsgi_req) {
        return 0;
}


void uwsgi_proto_iproto_setup(struct uwsgi_socket *uwsgi_sock) {
	uwsgi_sock->proto = uwsgi_proto_iproto_parser;
	uwsgi_sock->proto_accept = uwsgi_proto_base_accept;
	uwsgi_sock->proto_prepare_headers = uwsgi_proto_iproto_prepare_headers;
	uwsgi_sock->proto_add_header = uwsgi_proto_iproto_add_header;
	uwsgi_sock->proto_fix_headers = uwsgi_proto_iproto_fix_headers;
	uwsgi_sock->proto_read_body = uwsgi_proto_base_read_body;
	uwsgi_sock->proto_write = uwsgi_proto_base_write;
	uwsgi_sock->proto_writev = uwsgi_proto_base_writev;
	uwsgi_sock->proto_write_headers = uwsgi_proto_base_write;
	uwsgi_sock->proto_sendfile = uwsgi_proto_base_sendfile;
	uwsgi_sock->proto_close = uwsgi_proto_base_close;
	if (uwsgi.offload_threads > 0)
		uwsgi_sock->can_offload = 1;
}