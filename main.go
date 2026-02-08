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
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip nfsdtrace ./bpf/nfsd_trace.bpf.c -- -D__BPF_TRACING__ -D__TARGET_ARCH_x86 -O2 -g -target bpf -nostdinc -isystem /usr/lib/llvm-18/lib/clang/18/include -I. -I./libbpf/src -I./libbpf/include

var (
	nfsReadBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfs_read_bytes_total",
			Help: "Total bytes read from NFS by client and path",
		},
		[]string{"client", "path"},
	)
	nfsWriteBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfs_write_bytes_total",
			Help: "Total bytes written to NFS by client and path",
		},
		[]string{"client", "path"},
	)
	nfsReadOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfs_read_operations_total",
			Help: "Total number of NFS read operations by client and path",
		},
		[]string{"client", "path"},
	)
	nfsWriteOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfs_write_operations_total",
			Help: "Total number of NFS write operations by client and path",
		},
		[]string{"client", "path"},
	)
)

type DataT struct {
	Op   uint32
	Size uint32
	Addr uint32
	Path [64]byte
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

	// Open a perf event reader from the events map
	rd, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		log.Fatalf("creating perf reader: %v", err)
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
		os.Exit(0)
	}()

	// Read events
	for {
		record, err := rd.Read()
		if err != nil {
			log.Printf("reading from perf reader: %v", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("lost %d samples", record.LostSamples)
			continue
		}

		// Parse the event
		var data DataT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &data); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}

		// Convert IP address
		ip := net.IPv4(byte(data.Addr), byte(data.Addr>>8), byte(data.Addr>>16), byte(data.Addr>>24))

		// Extract path (null-terminated string)
		pathLen := 0
		for i, b := range data.Path {
			if b == 0 {
				pathLen = i
				break
			}
		}
		path := string(data.Path[:pathLen])

		// Determine operation and record metrics
		op := "READ"
		clientIP := ip.String()
		if data.Op == 1 {
			op = "WRITE"
			nfsWriteBytes.WithLabelValues(clientIP, path).Add(float64(data.Size))
			nfsWriteOperations.WithLabelValues(clientIP, path).Inc()
		} else {
			nfsReadBytes.WithLabelValues(clientIP, path).Add(float64(data.Size))
			nfsReadOperations.WithLabelValues(clientIP, path).Inc()
		}

		fmt.Printf("NFS %s | Client: %s | Size: %d bytes | Path: %s\n", op, clientIP, data.Size, path)
	}
}
