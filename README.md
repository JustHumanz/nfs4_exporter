# NFS eBPF Tracer

A high-performance NFS server monitoring tool built with eBPF that tracks read/write operations and exposes Prometheus metrics.

## Features

- 🚀 **Real-time NFS operation tracking** using eBPF kprobes
- 📊 **Prometheus metrics** with client IP and path labels
- 🔍 **Zero overhead** - runs in kernel space
- 📈 **Detailed statistics** - bytes transferred, operation counts per client/path
- 🎯 **NFSv4 support** - tracks `nfsd4_read` and `nfsd4_write` operations

## Requirements

- Linux kernel 5.8+ (tested on 6.8.0)
- Go 1.21+
- Clang/LLVM 10+
- libbpf headers
- Kernel headers for your running kernel
- Root/sudo access (required for loading eBPF programs)

### Ubuntu/Debian Installation

```bash
sudo apt update
sudo apt install -y clang llvm libelf-dev libbpf-dev \
    linux-headers-$(uname -r) pkg-config build-essential golang
```

## Building

### Clone with submodules

```bash
git clone --recurse-submodules <repository-url>
cd nfs-ebpf
```

If you already cloned without submodules:

```bash
git submodule update --init --recursive
```

### Build libbpf

```bash
cd libbpf/src
make
cd ../..
```

This will compile libbpf and generate the necessary headers in `libbpf/src/`.

### Generate vmlinux.h (if not present)

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### Build the tracer

```bash
go build -o nfsd-tracer
```

## Usage

### Run the tracer

```bash
sudo ./nfsd-tracer
```

The tracer will:
1. Attach kprobes to `nfsd4_read` and `nfsd4_write`
2. Start a Prometheus metrics server on port 2112
3. Print NFS operations to stdout as they occur

### Example output

```
2026/01/31 22:00:40 Attached kprobe to nfsd4_write
2026/01/31 22:00:40 Attached kprobe to nfsd4_read
2026/01/31 22:00:40 Prometheus metrics available at http://localhost:2112/metrics
2026/01/31 22:00:40 Listening for NFS events. Press Ctrl+C to exit.
NFS WRITE | Client: 192.168.18.142 | Size: 262144 bytes | Path: nfs_data
NFS READ | Client: 192.168.18.142 | Size: 16384 bytes | Path: nfs_data
NFS READ | Client: 192.168.18.142 | Size: 32768 bytes | Path: nfs_data
```

## Prometheus Metrics

The tracer exposes the following metrics at `http://localhost:2112/metrics`:

### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nfs_read_bytes_total` | Counter | `client`, `path` | Total bytes read from NFS |
| `nfs_write_bytes_total` | Counter | `client`, `path` | Total bytes written to NFS |
| `nfs_read_operations_total` | Counter | `client`, `path` | Total number of read operations |
| `nfs_write_operations_total` | Counter | `client`, `path` | Total number of write operations |

### Example Queries

**Read throughput (bytes/sec) over 1 minute:**
```promql
rate(nfs_read_bytes_total[1m])
```

**Write throughput per client:**
```promql
sum by (client) (rate(nfs_write_bytes_total[1m]))
```

**Total I/O operations per second:**
```promql
sum(rate(nfs_read_operations_total[1m])) + sum(rate(nfs_write_operations_total[1m]))
```

**Top paths by read traffic:**
```promql
topk(5, sum by (path) (rate(nfs_read_bytes_total[1m])))
```

### Scrape Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'nfs-tracer'
    static_configs:
      - targets: ['localhost:2112']
```

## Development

### Regenerate BPF code

If you modify `bpf/nfsd_trace.bpf.c`:

```bash
go generate
go build -o nfsd-tracer
```

### Project Structure

```
.
├── bpf/
│   └── nfsd_trace.bpf.c    # eBPF C program
├── libbpf/                  # libbpf submodule
├── main.go                  # Go application
├── vmlinux.h                # Kernel type definitions
├── go.mod                   # Go dependencies
└── README.md
```

## How It Works

1. **eBPF Program**: Attaches kprobes to kernel functions `nfsd4_read` and `nfsd4_write`
2. **Data Collection**: Captures client IP, path, and bytes transferred for each operation
3. **Perf Events**: Sends data from kernel to userspace via perf ring buffer
4. **Metrics Export**: Aggregates data and exposes as Prometheus counters

## Troubleshooting

### Permission denied when loading BPF program

Make sure you run with `sudo` and your kernel supports unprivileged BPF:

```bash
cat /proc/sys/kernel/unprivileged_bpf_disabled
# Should be 0 or 2 (with CAP_BPF)
```

### No events appearing

Verify NFS server is running and has active clients:

```bash
sudo systemctl status nfs-server
showmount -e localhost
```

### Compilation errors

Ensure kernel headers match your running kernel:

```bash
uname -r
ls /lib/modules/$(uname -r)/build
```

## License

[Your License Here]

## Contributing

Contributions welcome! Please open an issue or submit a pull request.
