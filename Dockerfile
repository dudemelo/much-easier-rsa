FROM alpine:latest

ENV EASYRSA_BATCH=1

RUN set -ex \
    && apk add --no-cache easy-rsa \
    && cd /usr/share/easy-rsa \ 
    && ./easyrsa init-pki \
    && ./easyrsa build-ca nopass
    
