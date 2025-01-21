# golang alpine
FROM golang:1.23.5-alpine AS builder

ARG TARGETARCH
ARG TARGETOS

RUN apk update \
 && apk add --no-cache \
            gcc \
            musl-dev \
 && update-ca-certificates

ENV GO111MODULE=on
ENV GOPATH=/

RUN mkdir /opt/go-didx509-toolkit && cd /opt/go-didx509-toolkit
COPY go.mod .
COPY go.sum .
RUN go mod download && go mod verify

COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-w -s" -o /opt/go-didx509-toolkit/issuer

# alpine
FROM alpine:3.21.2
RUN apk update \
  && apk add --no-cache \
             tzdata \
             curl
COPY --from=builder /opt/go-didx509-toolkit/issuer /usr/bin/issuer

# set container user to non-root
#RUN adduser -D -H -u 18081 issuer-usr
#USER 18081:18081

ENTRYPOINT ["/usr/bin/issuer"]
CMD ["--help"]


