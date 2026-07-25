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
	@$(GO) test ./... -coverprofile=cover.out

coverage:
	@$(GO) tool cover -func=cover.out

coverage-html:
	@$(GO) tool cover -html=cover.out -o coverage.html
	xdg-open coverage.html

clean:
	@$(REMOVE) -f csr-approver cover.out coverage.html
