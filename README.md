# XWF RADIUS Proxy
XWF RADIUS Proxy bridges plain RADIUS messages to ExpressWiFi V3 HTTP2 messages. 

## Requirements
* Code is designed to be cross-platform
* Works against any existing XWF V2 implementation

## Building RADIUS Proxy
autoreconf --install && ./configure --prefix=/build && make && make install

in order to emit Scribe-compatible logs, compile with the `LOG_TO_SCRIBE` flag:

autoreconf --install && ./configure --prefix=/build && make CFLAGS="-DLOG_TO_SCRIBE" && make install

## License
XWF RADIUS Proxy is MIT licensed, as found in the LICENSE file.
