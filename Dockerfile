# Stage 1: Build
FROM alpine:3.19 AS builder

# Vars
ARG NGINX_VERSION=1.26.3
ARG NGINX_SRC_URL=https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
ARG MODULE_NAME=ngx_http_x_cache_key_filter_module
ARG MODULE_PATH=/usr/src/${MODULE_NAME}
ARG NGINX_PATH=/opt/nginx_custom
ARG TMP_INSTALL_PATH=/tmp_install

# Nginx build deps
RUN apk update && apk add --no-cache build-base pcre-dev zlib-dev openssl-dev wget

# Download and extract Nginx project
WORKDIR /usr/src
RUN wget -O nginx.tar.gz ${NGINX_SRC_URL} \
 && tar -zxvf nginx.tar.gz \
 && rm nginx.tar.gz \
 && mv nginx-${NGINX_VERSION} nginx-src

# Copy the custom module source code and config file from repo
COPY ngx_http_x_cache_key_filter_module.c ${MODULE_PATH}/ngx_http_x_cache_key_filter_module.c
COPY config ${MODULE_PATH}/config

# Run ./configure with options to include custom module, debug, ssl, set prefix
WORKDIR /usr/src/nginx-src
RUN ./configure \
    --prefix=${NGINX_PATH} \
    --with-http_ssl_module \
    --with-debug \
    --add-module=${MODULE_PATH}

# Parallel compilation of Nginx
RUN make -j$(nproc)
# Package nicely together into tmp install dir
RUN make install DESTDIR=${TMP_INSTALL_PATH}


# Stage 2: Runtime
FROM alpine:3.19

# Vars
ARG NGINX_PATH=/opt/nginx_custom
ARG SSL_PATH=${NGINX_PATH}/ssl
ARG CONF_PATH=${NGINX_PATH}/conf
ARG TMP_INSTALL_PATH=/tmp_install

# Nginx runtime dependencies
RUN apk update && apk add --no-cache pcre zlib openssl ca-certificates

# Avoid being root, create "service" user with required permissions instead
RUN addgroup -S -g 101 nginx && adduser -S -G nginx -u 101 -s /sbin/nologin -D nginx

RUN mkdir -p ${SSL_PATH} && chmod 700 ${SSL_PATH}

# Generate self-signed certificate
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout ${SSL_PATH}/nginx-selfsigned.key \
      -out ${SSL_PATH}/nginx-selfsigned.crt \
      -subj "/CN=localhost" \
 && chown nginx:nginx ${SSL_PATH}* \
 && chmod 600 ${SSL_PATH}/nginx-selfsigned.key

# Copy the installed Nginx structure from the builder
COPY --from=builder ${TMP_INSTALL_PATH}/opt/nginx_custom ${NGINX_PATH}

RUN chown -R nginx:nginx ${NGINX_PATH}

COPY nginx.conf ${CONF_PATH}/nginx.conf

EXPOSE 8443

USER nginx

# Run Nginx in the foreground
STOPSIGNAL SIGQUIT
CMD ["/opt/nginx_custom/sbin/nginx", "-g", "daemon off;"]