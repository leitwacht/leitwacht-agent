//go:build linux

package enforcer

// The same slot-table object as ebpf_bk.go built with
// -DLEITWACHT_BK_NO_NETNS_COOKIE: its egress program never references
// bpf_get_netns_cookie, which cgroup_skb programs only get on newer
// kernels. LoadBuildKitEBPF falls back to it when the running kernel
// lacks the helper (features.HaveProgramHelper). Its maps and programs
// have the same names, so it loads into the same ebpfBKObjects.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 ebpfBKNC egress.c -- -DLEITWACHT_BK_MULTI -DLEITWACHT_BK_NO_NETNS_COOKIE -I/usr/include -I/usr/include/x86_64-linux-gnu -I. -O2 -Wall -g
