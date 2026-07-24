GO ?= go
REMOVE ?= rm

default: build

build: fmt
	@$(GO) mod download
	@$(GO) build -o csr-approver ./cmd

fmt:
	@$(GO) fmt ./...

vet:
	@$(GO) vet ./...

test: fmt vet
	@$(GO) test ./...

clean:
	@$(REMOVE) -f csr-approver
