package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip nfsdtrace ./bpf/nfsd_trace.bpf.c -- -D__BPF_TRACING__ -D__TARGET_ARCH_x86 -O2 -g -target bpf -nostdinc -isystem /usr/lib/llvm-18/lib/clang/18/include -I. -I./libbpf/src -I./libbpf/include

var (
	// NFS v4 metrics (with path)
	nfsReadBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfsd_read_bytes_total",
			Help: "Total bytes read from NFS v4 by client and path",
		},
		[]string{"client", "path", "version"},
	)
	nfsWriteBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfsd_write_bytes_total",
			Help: "Total bytes written to NFS v4 by client and path",
		},
		[]string{"client", "path", "version"},
	)
	nfsReadOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfsd_read_operations_total",
			Help: "Total number of NFS v4 read operations by client and path",
		},
		[]string{"client", "path", "version"},
	)
	nfsWriteOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfsd_write_operations_total",
			Help: "Total number of NFS v4 write operations by client and path",
		},
		[]string{"client", "path", "version"},
	)

	//
	max_pathStr    = os.Getenv("MAX_DEPTH_PATH")
	MAX_DEPTH_PATH = 2
)

// DataT mirrors struct data_t in the BPF program.
// IMPORTANT: field order and sizes must match the C struct exactly,
// including any implicit padding the compiler inserts for alignment.
type DataT struct {
	Op      uint32
	Size    uint32
	Addr4   uint32
	Prt     uint16
	_       uint16 // padding to keep Version 4-byte aligned
	Version uint32
	Path    [16][24]byte
}

func (d *DataT) pathString() string {
	return pathString(d)
}

func pathString(d *DataT) string {
	parts := make([]string, 0, len(d.Path))

	for _, chunk := range d.Path {
		if chunk[0] == 0 {
			break // first empty slot marks the end of real components
		}
		end := bytes.IndexByte(chunk[:], 0)
		if end < 0 {
			end = len(chunk)
		}
		parts = append(parts, string(chunk[:end]))
	}

	// components were captured leaf -> root; reverse for root -> leaf
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}

	if len(parts) == 0 {
		return "/"
	}

	if MAX_DEPTH_PATH >= len(parts) {
		return "/" + strings.Join(parts, "/")
	}
	return "/" + strings.Join(parts[:MAX_DEPTH_PATH], "/")
}

func init() {
	if max_pathStr != "" {
		var err error
		MAX_DEPTH_PATH, err = strconv.Atoi(max_pathStr)
		if err != nil {
			log.Fatalf("Invalid MAX_DEPTH_PATH, must be an integer: %v", err)
		}
	}
}

func main() {
	// Load pre-compiled programs and maps
	var objs nfsdtraceObjects
	if err := loadNfsdtraceObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach kprobe for nfsd4_write
	kpWrite, err := link.Kprobe("nfsd4_write", objs.KprobeNfsd4Write, nil)
	if err != nil {
		log.Fatalf("opening kprobe nfsd4_write: %v", err)
	}
	defer kpWrite.Close()
	log.Println("Attached kprobe to nfsd4_write")

	// Attach kprobe for nfsd4_read
	kpRead, err := link.Kprobe("nfsd4_read", objs.KprobeNfsd4Read, nil)
	if err != nil {
		log.Fatalf("opening kprobe nfsd4_read: %v", err)
	}
	defer kpRead.Close()
	log.Println("Attached kprobe to nfsd4_read")

	// Attach kprobe for nfsd3_proc_write
	kpNfsd3Write, err := link.Kprobe("nfsd3_proc_write", objs.KprobeNfsd3ProcWrite, nil)
	if err != nil {
		log.Fatalf("opening kprobe nfsd3_proc_write: %v", err)
	}
	defer kpNfsd3Write.Close()
	log.Println("Attached kprobe to nfsd3_proc_write")

	// Attach kretprobe for nfsd3_proc_write
	kpNfsd3WriteRet, err := link.Kretprobe("nfsd3_proc_write", objs.KretprobeNfsd3ProcWrite, nil)
	if err != nil {
		log.Fatalf("opening kretprobe nfsd3_proc_write: %v", err)
	}
	defer kpNfsd3WriteRet.Close()
	log.Println("Attached kretprobe to nfsd3_proc_write")

	// Attach kprobe for nfsd3_proc_read
	kpNfsd3Read, err := link.Kprobe("nfsd3_proc_read", objs.KprobeNfsd3ProcRead, nil)
	if err != nil {
		log.Fatalf("opening kprobe nfsd3_proc_read: %v", err)
	}
	defer kpNfsd3Read.Close()
	log.Println("Attached kprobe to nfsd3_proc_read")

	// Attach kretprobe for nfsd3_proc_read
	kpNfsd3ReadRet, err := link.Kretprobe("nfsd3_proc_read", objs.KretprobeNfsd3ProcRead, nil)
	if err != nil {
		log.Fatalf("opening kretprobe nfsd3_proc_read: %v", err)
	}
	defer kpNfsd3ReadRet.Close()
	log.Println("Attached kretprobe to nfsd3_proc_read")

	// Open a ringbuf reader from the events map
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Start Prometheus metrics HTTP server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Println("Prometheus metrics available at http://localhost:2112/metrics")
		if err := http.ListenAndServe(":2112", nil); err != nil {
			log.Fatalf("failed to start metrics server: %v", err)
		}
	}()

	log.Println("Listening for NFS events. Press Ctrl+C to exit.")

	// Handle Ctrl+C
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		log.Println("\nReceived signal, exiting...")
		rd.Close() // unblocks rd.Read() below so the program can exit cleanly
		os.Exit(0)
	}()

	// Read events
	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				// reader was closed during shutdown, exit the loop quietly
				return
			}
			log.Printf("reading from ringbuf: %v", err)
			break
		}

		// Parse the event
		var data DataT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &data); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}

		// Convert IP address
		ip := net.IPv4(byte(data.Addr4), byte(data.Addr4>>8), byte(data.Addr4>>16), byte(data.Addr4>>24))
		path := data.pathString()

		// Determine operation and record metrics
		op := "READ"
		clientIP := ip.String()
		version := fmt.Sprintf("%d", data.Version)

		switch data.Op {
		case 1:
			op = "WRITE"
			nfsWriteBytes.WithLabelValues(clientIP, path, version).Add(float64(data.Size))
			nfsWriteOperations.WithLabelValues(clientIP, path, version).Inc()
		default:
			nfsReadBytes.WithLabelValues(clientIP, path, version).Add(float64(data.Size))
			nfsReadOperations.WithLabelValues(clientIP, path, version).Inc()
		}

		fmt.Printf("NFS %s | Client: %s | Size: %d bytes | Path: %s | Version: %s\n", op, clientIP, data.Size, path, version)
	}
}
