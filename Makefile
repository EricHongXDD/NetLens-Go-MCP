GO ?= go

.PHONY: build test race vet run demo

build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/netlens ./cmd/netlens

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

run: build
	./bin/netlens serve --data-dir "$(CURDIR)/.netlens"

demo:
	$(GO) run ./examples/demo-server
