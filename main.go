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
	// NFS v4 metrics (with path)
	nfs4ReadBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfs4_read_bytes_total",
			Help: "Total bytes read from NFS v4 by client and path",
		},
		[]string{"client", "path", "version"},
	)
	nfs4WriteBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfs4_write_bytes_total",
			Help: "Total bytes written to NFS v4 by client and path",
		},
		[]string{"client", "path", "version"},
	)
	nfs4ReadOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfs4_read_operations_total",
			Help: "Total number of NFS v4 read operations by client and path",
		},
		[]string{"client", "path", "version"},
	)
	nfs4WriteOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfs4_write_operations_total",
			Help: "Total number of NFS v4 write operations by client and path",
		},
		[]string{"client", "path", "version"},
	)

	// NFS v3 metrics (without path)
	nfs3ReadBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfs3_read_bytes_total",
			Help: "Total bytes read from NFS v3 by client",
		},
		[]string{"client", "version"},
	)
	nfs3WriteBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfs3_write_bytes_total",
			Help: "Total bytes written to NFS v3 by client",
		},
		[]string{"client", "version"},
	)
	nfs3ReadOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfs3_read_operations_total",
			Help: "Total number of NFS v3 read operations by client",
		},
		[]string{"client", "version"},
	)
	nfs3WriteOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfs3_write_operations_total",
			Help: "Total number of NFS v3 write operations by client",
		},
		[]string{"client", "version"},
	)
)

type DataT struct {
	Op   uint32
	Size uint32
	Addr uint32
	Version uint32
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


	// Attach kprobe for nfsd3_proc_write
	kpNfsd3Write, err := link.Kprobe("nfsd3_proc_write", objs.KprobeNfsd3ProcWrite, nil)
	if err != nil {
		log.Fatalf("opening kprobe nfsd3_proc_write: %v", err)
	}
	defer kpNfsd3Write.Close()
	log.Println("Attached kprobe to nfsd3_proc_write")

	// Attach kprobe for nfsd3_proc_read
	kpNfsd3Read, err := link.Kprobe("nfsd3_proc_read", objs.KprobeNfsd3ProcRead, nil)
	if err != nil {
		log.Fatalf("opening kprobe nfsd3_proc_read: %v", err)
	}
	defer kpNfsd3Read.Close()
	log.Println("Attached kprobe to nfsd3_proc_read")

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
		version := fmt.Sprintf("%d", data.Version)
		
		if data.Version == 4 {
			// NFS v4 metrics (with path)
			if data.Op == 1 {
				op = "WRITE"
				nfs4WriteBytes.WithLabelValues(clientIP, path, version).Add(float64(data.Size))
				nfs4WriteOperations.WithLabelValues(clientIP, path, version).Inc()
			} else {
				nfs4ReadBytes.WithLabelValues(clientIP, path, version).Add(float64(data.Size))
				nfs4ReadOperations.WithLabelValues(clientIP, path, version).Inc()
			}
		} else if data.Version == 3 {
			// NFS v3 metrics (without path)
			if data.Op == 1 {
				op = "WRITE"
				nfs3WriteBytes.WithLabelValues(clientIP, version).Add(float64(data.Size))
				nfs3WriteOperations.WithLabelValues(clientIP, version).Inc()
			} else {
				nfs3ReadBytes.WithLabelValues(clientIP, version).Add(float64(data.Size))
				nfs3ReadOperations.WithLabelValues(clientIP, version).Inc()
			}
		}

		fmt.Printf("NFS %s | Client: %s | Size: %d bytes | Path: %s | Version: %s\n", op, clientIP, data.Size, path, version)
	}
}
