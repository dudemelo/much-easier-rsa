FROM golang:alpine AS builder

WORKDIR /go/src/app

COPY . .

RUN set -ex \
    && go mod download \
    && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

FROM alpine:latest

ENV EASYRSA_BATCH=1

WORKDIR /usr/share/easy-rsa

COPY --from=builder /go/src/app/app /usr/bin/app

RUN set -ex \
    # for debugging
    && apk add --no-cache vim \
    && apk add --no-cache easy-rsa \
    && ./easyrsa init-pki \
    && ./easyrsa build-ca nopass

CMD ["app"]
    
