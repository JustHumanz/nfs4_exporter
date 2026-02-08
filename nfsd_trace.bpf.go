//go:build ignore
// +build ignore

package main

// This file exists to prevent Go from trying to compile nfsd_trace.bpf.c
// The BPF C code is compiled separately by bpf2go and embedded in the generated Go files.
