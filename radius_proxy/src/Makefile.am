bin_PROGRAMS = radius_http_proxy
radius_http_proxy_SOURCES = http2_request_handler.c udp_request_handler.c utils/jsmn.c utils/encode.c utils/decode.c utils/utils.c coa_sse_handler.c radius_proxy.c config_parser.c main.c
radius_http_proxy_LDADD = -lev -lcurl
radius_http_proxy_LDFLAGS =  -L/opt/local/lib
radius_http_proxy_CFLAGS = -Wall -Werror -Iinclude -fno-strict-aliasing
