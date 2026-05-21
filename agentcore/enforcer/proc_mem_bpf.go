//go:build linux

package enforcer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 procMem proc_mem.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu -I. -O2 -Wall -g
