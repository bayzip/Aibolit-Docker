FROM alpine:latest
LABEL maintainer="Bayu Adin H <bayu.adin.h@mail.ugm.ac.id>"
LABEL description="Docker with NGINX + FPM"

ENV MYWEB /usr/share/nginx/html

RUN apk add --update php7 \
    unzip \
    wget \
    curl && \
    rm -rf /var/cache/apk/*

COPY ai-bolit/ /opt/aibolit
COPY tools /opt/tools
COPY script.sh /starter.sh

ENTRYPOINT  ["sh", "/starter.sh"]
