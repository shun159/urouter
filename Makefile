.PHONY: all
all: bin/urouter

.ONESHELL:
SHELL = /bin/bash

LDFLAGS := -ldflags="-s -w -extldflags \"-static"\"
SOURCES := $(shell find . -type f -name '*.go')

bin/urouter: $(SOURCES) gen
	@go build $(LDFLAGS) -o ./bin/urouter ./cmd/urouter

.PHONY: gen
gen: export BPF_CLANG := clang
gen:
	@go generate pkg/coreelf/elf.go

clean:
	rm -rf $(OUTPUT_DIR)
