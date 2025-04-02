# Makefile for goat_voter

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GO_IMAGE_VERSION=1.23.3-bullseye
BINARY_NAME=goat-relayer

# Build binary
all: build

build:
	$(GOBUILD) -o $(BINARY_NAME) -v ./cmd

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

test:
	$(GOTEST) -v ./...

deps:
	$(GOGET) -u ./...

run:
	$(GOBUILD) -o $(BINARY_NAME) -v ./cmd && ./$(BINARY_NAME)

docker-build-all:
	docker buildx build --platform linux/amd64,linux/arm64 -t goatnetwork/goat-relayer:latest --push .

docker-build:
	docker buildx build --platform linux/amd64 -t goatnetwork/goat-relayer:latest --load .

docker-build-x:
	docker buildx build --platform linux/arm64 -t goatnetwork/goat-relayer:latest --load .

docker-test:
	docker run --rm -v $(shell pwd):/app -w /app golang:$(GO_IMAGE_VERSION) go test -v ./...

.PHONY: all build clean test deps run docker-build docker-build-all docker-build-x docker-test