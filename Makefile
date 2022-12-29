.ONESHELL:
SHELL = /bin/bash

.PHONY: gen
gen: export BPF_CLANG := clang
gen:
	@go generate pkg/coreelf/elf.go

clean:
	rm -rf $(OUTPUT_DIR)
