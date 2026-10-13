FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Rome

ENV APT_DEPS git \
		python3 \
		python-is-python3 \
		pip \
		libgomp1 nano iproute2

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iproute2 \
    tzdata \
    openssl \
    bash \
    nginx \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir /etc/nginx/ssl
RUN mkdir /etc/nginx/ssl/private
RUN mkdir /etc/nginx/ssl/certs
COPY nginx_server/default /etc/nginx/sites-enabled/
COPY nginx_server/nginx.conf /etc/nginx/
COPY ./docker/server-entrypoint.sh /usr/local/bin/server-entrypoint.sh
RUN chmod +x /usr/local/bin/server-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/server-entrypoint.sh"]

