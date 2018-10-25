FROM alpine:latest
LABEL maintainer="Bayu Adin H <bayu.adin.h@mail.ugm.ac.id>"
LABEL description="Docker with NGINX + FPM"

ENV PHPVERSION 7
ENV PHPMODULE="php${PHPVERSION} \
    php${PHPVERSION}-fpm \
    php${PHPVERSION}-opcache \
    php${PHPVERSION}-curl \
    php${PHPVERSION}-intl \
    php${PHPVERSION}-iconv \
    php${PHPVERSION}-mcrypt  \
    php${PHPVERSION}-bcmath \
    php${PHPVERSION}-common \
    php${PHPVERSION}-dev \
    php${PHPVERSION}-gd \
    php${PHPVERSION}-mbstring \
    php${PHPVERSION}-mysqlnd \
    php${PHPVERSION}-pdo \
    php${PHPVERSION}-soap \
    php${PHPVERSION}-xml \
    php${PHPVERSION}-xmlrpc"
ENV PORT_NGINX

RUN apk add --update nginx && \
    apk add ${PHPMODULE} && \
    apk add supervisor && \
    apk add unzip && \
    rm -rf /var/cache/apk/* && \
    mkdir -p /tmp/nginx/ && \
    mkdir -p /usr/share/nginx/html && \
    echo "<?php phpinfo(); ?>" > /usr/share/nginx/html/index.php

ADD config/nginx/nginx.conf /etc/nginx/nginx.conf
ADD config/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf
ADD config/fpm/www.conf /etc/php7/php-fpm.d/www.conf
ADD script/starter.sh /starter.sh
ADD script/supervisord.conf /etc/supervisord.conf

EXPOSE 80/tcp 8080/tcp 8181/tcp 9000/tcp

HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD curl -s --fail http://localhost:${PORT_NGINX}  || exit 1

ENTRYPOINT  ["sh", "/starter.sh"]
