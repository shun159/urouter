.PHONY: all
all: bin/urouter

.ONESHELL:
SHELL = /bin/bash

LDFLAGS := -ldflags="-s -w -extldflags \"-static"\"
GO_SOURCES := $(shell find . -type f -name '*.go')
bin/urouter: $(GO_SOURCES) gen
	@go build $(LDFLAGS) -o ./bin/urouter ./cmd/urouter

.PHONY: run
run:
	@go run $(LDFLAGS) ./cmd/urouter

.PHONY: gen
gen: export BPF_CLANG := clang
gen:
	@go generate pkg/coreelf/elf.go

.PHONY: format
format:
	@clang-format -i $(wildcard bpf/*.[c|h])

clean:
	rm -rf $(OUTPUT_DIR)
