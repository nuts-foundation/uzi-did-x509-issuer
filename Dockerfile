# golang alpine
FROM golang:1.23.1-alpine AS builder

ARG TARGETARCH
ARG TARGETOS

ARG GIT_COMMIT=0
ARG GIT_BRANCH=master
ARG GIT_VERSION=undefined

LABEL maintainer="roland@headease.nl"

RUN apk update \
 && apk add --no-cache \
            gcc \
            musl-dev \
 && update-ca-certificates

ENV GO111MODULE=on
ENV GOPATH=/

RUN mkdir /opt/pki-overheid-issuer && cd /opt/pki-overheid-issuer
COPY go.mod .
COPY go.sum .
RUN go mod download && go mod verify

COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-w -s " -o /opt/pki-overheid-issuer/pki-overheid-issuer

# alpine
FROM alpine:3.20.3
RUN apk update \
  && apk add --no-cache \
             tzdata \
             curl \
  && update-ca-certificates
COPY --from=builder /opt/pki-overheid-issuer/pki-overheid-issuer /usr/bin/pki-overheid-issuer

RUN adduser -D -H -u 18081 pki-overheid-issuer-usr
USER 18081:18081
WORKDIR /pki-overheid-issuer
ENTRYPOINT ["/usr/bin/pki-overheid-issuer"]
CMD ["--help"]


