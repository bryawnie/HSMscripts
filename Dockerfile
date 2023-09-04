FROM golang:1.21-alpine AS builder

RUN apk --no-cache add gcc g++ make
COPY . /go/app/
WORKDIR /go/app/

RUN go build -o ./bin/app

# Run
FROM alpine:3.18
COPY --from=builder /go/app/bin /go/bin

ARG SUBCOMMAND
ARG PKCS11_MODULE_LOCATION
ARG USER_PIN
ARG KEY_LABEL
ARG MESSAGE
ARG SIGNATURE


CMD /go/bin/app $SUBCOMMAND