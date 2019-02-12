FROM alpine:latest
LABEL maintainer="Bayu Adin H <bayu.adin.h@mail.ugm.ac.id>"
LABEL description="Docker with NGINX + FPM"

ENV MYWEB /usr/share/nginx/html

RUN apk add php7 \
    unzip \
    wget \
    curl && \
    rm -rf /var/cache/apk/*

COPY aibolit.zip /opt/aibolit.zip
COPY script.sh /starter.sh

ENTRYPOINT  ["sh", "/starter.sh"]
