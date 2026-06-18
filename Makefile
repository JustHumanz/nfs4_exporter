# Makefile generated from Dockerfile

BINARY := nfsd-tracer
IMAGE  := nfsd-tracer:latest

.PHONY: all build deps libbpf gen docker clean help

all: build

help:
	@echo "Makefile targets:"
	@echo "  make build   - build the binary locally"
	@echo "  make libbpf  - build libbpf (runs make in libbpf/src)"
	@echo "  make gen     - generate artifacts (vmlinux.h if missing) and run go generate"
	@echo "  make docker  - build Docker image using Dockerfile"
	@echo "  make clean   - remove binary"

build: deps libbpf gen
	@echo "Building $(BINARY)..."
	go build -o $(BINARY)

deps:
	@echo "Updating submodules and downloading go modules..."
	git submodule update --init --recursive
	go mod download

libbpf:
	@if [ -d libbpf/src ]; then \
		echo "Building libbpf..."; \
		cd libbpf/src && make; \
	else \
		echo "libbpf/src not found, skipping"; \
	fi

gen:
	@echo "Generating vmlinux.h if missing and running go generate..."
	@if [ ! -f vmlinux.h ]; then \
		if command -v bpftool >/dev/null 2>&1; then \
			bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h || true; \
		fi; \
		if [ ! -f vmlinux.h ]; then \
			wget -q https://storage.humanz.moe/tools/vmlinux.h -O vmlinux.h || \
			echo "Warning: Could not download vmlinux.h, please obtain it manually"; \
		fi; \
	fi
	go generate

docker:
	@echo "Building Docker image $(IMAGE)..."
	docker build -t $(IMAGE) .

clean:
	@echo "Cleaning up..."
	rm -f $(BINARY)
