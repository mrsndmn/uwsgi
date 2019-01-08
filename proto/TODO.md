each iproto reqtype compares any kind of packed data (json, cbor, protobuf)g

iproto req_type to unpack_type:
    1 => GET
    2 => HEAD
    4 => POST
    8 => PUT
    16 => DELETE
    32 => CONNECT
    64 => OPTIONS
    128 => TRACE
    256 => PATCH