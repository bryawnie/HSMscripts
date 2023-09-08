FROM golang:1.21-alpine AS builder

RUN apk --no-cache add gcc g++ make
COPY . /go/app/
WORKDIR /go/app/

RUN go build -o ./bin/app

# Runner Container
FROM alpine:3.18

RUN apk --no-cache add gcc g++ && ln -s /lib/libc.musl-x86_64.so.1 /lib/ld-linux-x86-64.so.2

COPY --from=builder /go/app/bin /go/bin

RUN mkdir -p /usr/safenet/lunaclient
COPY lunaclient/ /usr/safenet/lunaclient

ARG SUBCOMMAND
ARG MODULE_LOCATION
ARG TOKEN_PIN
ARG KEY_LABEL
ARG MESSAGE
ARG SIGNATURE

ENV SUBCOMMAND=$SUBCOMMAND
ENV MODULE_LOCATION=$MODULE_LOCATION
ENV TOKEN_PIN=$TOKEN_PIN
ENV KEY_LABEL=$KEY_LABEL
ENV MESSAGE=$MESSAGE
ENV SIGNATURE=$SIGNATURE

CMD /go/bin/app $SUBCOMMAND -l $MODULE_LOCATION -p $TOKEN_PIN -k $KEY_LABEL -m "${MESSAGE}"

