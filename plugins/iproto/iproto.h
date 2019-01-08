
struct __attribute__ ((packed)) iproto_header {
	uint32_t type;
	uint32_t body_length;
	uint32_t request_id;
};

const size_t ih_len = sizeof(struct iproto_header); // iproto headers length = 24 bytes