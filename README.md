# NFS eBPF Tracer

A high-performance NFS server monitoring tool built with eBPF that tracks read/write operations and exposes Prometheus metrics.

## Features

- 🚀 **Real-time NFS operation tracking** using eBPF kprobes
- 📊 **Prometheus metrics** with client IP and path labels
- 🔍 **Zero overhead** - runs in kernel space
- 📈 **Detailed statistics** - bytes transferred, operation counts per client/path
- 🎯 **NFSv4 support** - tracks `nfsd4_read` and `nfsd4_write` operations
- 🧩 **NFSv3 support** - tracks `nfsd3_proc_write` (bytes and ops)

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
git clone --recurse-submodules git@github.com:JustHumanz/nfs4_exporter.git
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
go generate
go build -o nfsd-tracer
```

## Docker

### Build Docker image

```bash
./build-docker.sh
```

Or manually:

```bash
docker build -t nfs4-exporter:latest .
```

### Run with Docker

```bash
docker run --rm --privileged \
  --pid=host \
  --network=host \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  nfs4-exporter:latest
```

**Required Docker flags:**
- `--privileged`: Required to load eBPF programs
- `--pid=host`: Access host kernel for kprobes
- `--network=host`: Metrics accessible on host's localhost:2112
- `-v /sys/kernel/debug:/sys/kernel/debug:ro`: Kernel debugging interface

## Usage

### Run the tracer

```bash
sudo ./nfsd-tracer
```

The tracer will:
1. Attach kprobes to `nfsd4_read`, `nfsd4_write`, and `nfsd3_proc_write`
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
| `nfs4_read_bytes_total` | Counter | `client`, `path`, `version` | Total bytes read from NFS v4 |
| `nfs4_write_bytes_total` | Counter | `client`, `path`, `version` | Total bytes written to NFS v4 |
| `nfs4_read_operations_total` | Counter | `client`, `path`, `version` | Total number of NFS v4 read operations |
| `nfs4_write_operations_total` | Counter | `client`, `path`, `version` | Total number of NFS v4 write operations |
| `nfs3_read_bytes_total` | Counter | `client`, `version` | Total bytes read from NFS v3 |
| `nfs3_write_bytes_total` | Counter | `client`, `version` | Total bytes written to NFS v3 |
| `nfs3_read_operations_total` | Counter | `client`, `version` | Total number of NFS v3 read operations |
| `nfs3_write_operations_total` | Counter | `client`, `version` | Total number of NFS v3 write operations |

### Example Queries

**Read throughput (bytes/sec) over 1 minute (NFS v4):**
```promql
rate(nfs4_read_bytes_total[1m])
```

**Write throughput per client (NFS v4):**
```promql
sum by (client) (rate(nfs4_write_bytes_total[1m]))
```

**Total I/O operations per second (NFS v4):**
```promql
sum(rate(nfs4_read_operations_total[1m])) + sum(rate(nfs4_write_operations_total[1m]))
```

**Top paths by read traffic (NFS v4):**
```promql
topk(5, sum by (path) (rate(nfs4_read_bytes_total[1m])))
```

**Read throughput (bytes/sec) over 1 minute (NFS v3):**
```promql
rate(nfs3_read_bytes_total[1m])
```

**Write throughput per client (NFS v3):**
```promql
sum by (client) (rate(nfs3_write_bytes_total[1m]))
```

**Total I/O operations per second (NFS v3):**
```promql
sum(rate(nfs3_read_operations_total[1m])) + sum(rate(nfs3_write_operations_total[1m]))
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

1. **eBPF Program**: Attaches kprobes to kernel functions `nfsd4_read`, `nfsd4_write`, and `nfsd3_proc_write`
2. **Data Collection**: Captures client IP and bytes transferred for each operation; path is captured for NFSv4 only
3. **Perf Events**: Sends data from kernel to userspace via perf ring buffer
4. **Metrics Export**: Aggregates data and exposes as Prometheus counters

## Notes on NFSv3

- NFSv3 does **not** include a stable, easily extractable export path in the same way as NFSv4.
- As a result, **path metrics are not available for NFSv3**; metrics will be labeled by client only for NFSv3 operations.

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

Idk, just use it lol

## Contributing

Contributions welcome! Please open an issue or submit a pull request.
