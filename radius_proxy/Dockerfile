# build radius http proxy
FROM alpine as builder
RUN apk add build-base libev-dev automake autoconf curl-dev
COPY radius_proxy/ /src/radius_http_proxy
WORKDIR /src/radius_http_proxy
RUN autoreconf --install && ./configure --prefix=/build && make CFLAGS="-DLOG_TO_SCRIBE" && make install

FROM 040765742554.dkr.ecr.eu-west-1.amazonaws.com/scribedog:latest
RUN apk add libev curl gettext
WORKDIR /app
COPY --from=builder /build/bin/radius_http_proxy ./radius_proxy
COPY radius_proxy/radius_proxy.config.template ./radius_proxy.config.template
COPY radius_proxy/docker-entrypoint.sh /usr/local/bin/
CMD ["docker-entrypoint.sh"]
