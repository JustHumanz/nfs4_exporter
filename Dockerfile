# Build stage
FROM ubuntu:22.04 AS builder

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    linux-headers-generic \
    pkg-config \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.25
RUN wget https://go.dev/dl/go1.25.6.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.25.6.linux-amd64.tar.gz && \
    rm go1.25.6.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Set working directory
WORKDIR /build
COPY . .

# RUN submodule update --init --recursive
RUN git submodule update --init --recursive

# Build libbpf
WORKDIR /build/libbpf/src
RUN make

# Copy application source
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

# Generate vmlinux.h if not present
RUN if [ ! -f vmlinux.h ]; then \
    apt-get update && apt-get install -y linux-tools-generic bpftool && \
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h || \
    echo "Warning: Could not generate vmlinux.h, fetch it manually"; \
    wget https://storage.humanz.moe/tools/vmlinux.h -O vmlinux.h || \
    echo "ERROR: Could not download vmlinux.h"; \
    fi

# Generate BPF code and build the application
RUN go generate && go build -o nfsd-tracer

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libelf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /build/nfsd-tracer /usr/local/bin/nfsd-tracer

# Expose Prometheus metrics port
EXPOSE 2112

# Run as root (required for eBPF)
USER root

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/nfsd-tracer"]
