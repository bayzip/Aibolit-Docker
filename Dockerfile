FROM alpine:latest
LABEL maintainer="Bayu Adin H <bayu.adin.h@mail.ugm.ac.id>"
LABEL description="Docker with NGINX + FPM"

ENV MYWEB /usr/share/nginx/html

<<<<<<< HEAD
RUN apk add --update php7 \
=======
RUN apk add php7 \
>>>>>>> b3a8e1731c1cd1477104e52d775a033bbdab7f68
    unzip \
    wget \
    curl && \
    rm -rf /var/cache/apk/*

COPY ai-bolit/ /opt/aibolit
COPY tools /opt/tools
COPY script.sh /starter.sh

ENTRYPOINT  ["sh", "/starter.sh"]
