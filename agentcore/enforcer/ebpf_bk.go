//go:build linux

package enforcer

// The BuildKit slot-table object: egress.c compiled with
// -DLEITWACHT_BK_MULTI (see egress_bk.h). Generated types are prefixed
// ebpfBK (ebpfBKObjects, loadEbpfBK, ...). The per-pod object (ebpf.go)
// is built from the same source without the define and is unchanged.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 ebpfBK egress.c -- -DLEITWACHT_BK_MULTI -I/usr/include -I/usr/include/x86_64-linux-gnu -I. -O2 -Wall -g
