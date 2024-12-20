.PHONY: test run-generators all-docs

run-generators: gen-mocks

install-tools:
	go install go.uber.org/mock/mockgen@v0.4.0
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.60.1

gen-mocks:

lint:
	golangci-lint run -v

test:
	go test ./...

OUTPUT ?= "$(shell pwd)/issuer"
GIT_COMMIT ?= "$(shell git rev-list -1 HEAD)"
GIT_BRANCH ?= "$(shell git symbolic-ref --short HEAD)"
GIT_VERSION ?= "$(shell git name-rev --tags --name-only $(shell git rev-parse HEAD))"
build:
	go build -ldflags="-w -s" -o "${OUTPUT}"

docker:
	docker build --build-arg GIT_COMMIT=${GIT_COMMIT} --build-arg GIT_BRANCH=${GIT_BRANCH} --build-arg GIT_VERSION=${GIT_VERSION} -t github.com/Headease/pki-overheid-issuer:master .

docker-dev: docker
	docker build -t nutsfoundation/nuts-node:dev development/dev-image

