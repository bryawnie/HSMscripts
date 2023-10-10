FROM golang:1.21-alpine AS builder

RUN apk --no-cache add gcc g++ make
COPY . /go/app/
WORKDIR /go/app/

RUN go build -o ./bin/app

# Runner Container
FROM alpine:3.18

RUN apk --no-cache add gcc g++ && ln -s /lib/libc.musl-x86_64.so.1 /lib/ld-linux-x86-64.so.2

COPY --from=builder /go/app/bin /go/bin
COPY --from=builder /go/app/db/dbConfig.json /go/bin/db/dbConfig.json

RUN mkdir -p /usr/safenet/lunaclient
COPY lunaclient/ /usr/safenet/lunaclient

ARG CERTIFICATE_PATH
COPY ${CERTIFICATE_PATH} /go/bin/cert.pem

ARG POSTGRES_HOST
RUN sed -i "s/DB_HOST/${POSTGRES_HOST}/g" /go/bin/db/dbConfig.json
ARG POSTGRES_USER
RUN sed -i "s/DB_USER/${POSTGRES_USER}/g" /go/bin/db/dbConfig.json
ARG POSTGRES_PASSWORD
RUN sed -i "s/DB_PASSWORD/${POSTGRES_PASSWORD}/g" /go/bin/db/dbConfig.json
ARG POSTGRES_DB
RUN sed -i "s/DB_NAME/${POSTGRES_DB}/g" /go/bin/db/dbConfig.json

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
ENV CERTIFICATE_PATH=$CERTIFICATE_PATH

CMD /go/bin/app $SUBCOMMAND -l $MODULE_LOCATION -p $TOKEN_PIN -k $KEY_LABEL -m "${MESSAGE}" -s "${SIGNATURE}" -c /go/bin/cert.pem

