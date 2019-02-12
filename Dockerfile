FROM alpine:latest
LABEL maintainer="Bayu Adin H <bayu.adin.h@mail.ugm.ac.id>"
LABEL description="Docker with NGINX + FPM"

ENV PATH /usr/share/nginx/html

RUN apk add php7
RUN apk add unzip
RUN apk add wget
RUN apk add curl
RUN apk add rm -rf /var/cache/apk/*

COPY aibolit.zip /opt/aibolit.zip
COPY script.sh /starter.sh

ENTRYPOINT  ["sh", "/starter.sh"]