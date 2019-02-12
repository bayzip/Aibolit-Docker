FROM alpine:latest
LABEL maintainer="Bayu Adin H <bayu.adin.h@mail.ugm.ac.id>"
LABEL description="Docker with NGINX + FPM"

ENV PATH /usr/share/nginx/html
ENV PHPVERSION 7
ENV PHPMODULE="php${PHPVERSION} \
    php${PHPVERSION}-fpm \
    php${PHPVERSION}-curl \
    php${PHPVERSION}-common"

RUN apk add --no-cache \
    ${PHPMODULE} \
    unzip \
    wget \
    curl \
    rm -rf /var/cache/apk/*

COPY aibolit.zip /opt/aibolit.zip
COPY script.sh /starter.sh

ENTRYPOINT  ["sh", "/starter.sh"]