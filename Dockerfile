# golang versions must be greater than or equal to 1.12
FROM golang:1.12-alpine3.9 as builder
LABEL maintainer="zouguangxian <zouguangxian@hyn.space>"

RUN apk add --update --no-cache git build-base

COPY ./ $GOPATH/src/github.com/caddyserver/caddy

WORKDIR $GOPATH/src/github.com/caddyserver/caddy/caddy
RUN GO111MODULE=on go mod vendor && GODEBUG=tls13=1 go build -a -ldflags="-w -s" && go install

###
FROM alpine:3.9
LABEL maintainer="zouguangxian <zouguangxian@hyn.space>"

RUN apk add --update --no-cache ca-certificates wget tzdata

COPY --from=builder /go/bin/caddy /usr/local/bin/

RUN mkdir -p /var/log/caddy/ && mkdir -p /etc/caddy/

EXPOSE 443
ENTRYPOINT ["/usr/local/bin/caddy"]
