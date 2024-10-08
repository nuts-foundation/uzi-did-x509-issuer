.PHONY: test run-generators all-docs

run-generators: gen-mocks gen-api gen-protobuf

install-tools:
	go install go.uber.org/mock/mockgen@v0.4.0
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.60.1

gen-mocks:
	mockgen -destination=ura_vc/did_x509_mock.go -package=ura_vc -source=ura_vc/did_x509.go
	mockgen -destination=ura_vc/x509_cert_mock.go -package=ura_vc -source=ura_vc/x509_cert.go
	mockgen -destination=ura_vc/pem_reader_mock.go -package=ura_vc -source=ura_vc/pem_reader.go

lint:
	golangci-lint run -v

test:
	go test ./...

OUTPUT ?= "$(shell pwd)/issuer"
GIT_COMMIT ?= "$(shell git rev-list -1 HEAD)"
GIT_BRANCH ?= "$(shell git symbolic-ref --short HEAD)"
GIT_VERSION ?= "$(shell git name-rev --tags --name-only $(shell git rev-parse HEAD))"
build:
	go build -tags jwx_es256k -ldflags="-w -s -o ${OUTPUT}"

docker:
	docker build --build-arg GIT_COMMIT=${GIT_COMMIT} --build-arg GIT_BRANCH=${GIT_BRANCH} --build-arg GIT_VERSION=${GIT_VERSION} -t github.com/Headease/pki-overheid-issuer:master .

docker-dev: docker
	docker build -t nutsfoundation/nuts-node:dev development/dev-image

