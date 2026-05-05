//go:build linux

package enforcer

// -Wno-unused-parameter silences warnings on the `ctx` parameter
// injected by BPF_KPROBE / BPF_PROG macro expansion; those parameters
// are part of the fixed hook signature and are frequently unused in
// the body. All other warnings kept on (-Wall).
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 dnspid dns_pid.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu -I. -O2 -Wall -Wno-unused-parameter -g
