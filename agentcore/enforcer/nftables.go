//go:build linux

package enforcer

import (
	"encoding/binary"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// setupDNSRedirect creates nftables rules to redirect outbound DNS (port 53)
// to the local DNS proxy on port 15353. The conn must be created inside the
// target container's network namespace.
//
// Packets carrying agentMark (set via SO_MARK on the proxy's upstream
// socket) are accepted without redirect to prevent a loop when the proxy
// forwards queries to Docker's embedded DNS (127.0.0.11).
func setupDNSRedirect(conn *nftables.Conn) error {
	// Delete any stale leitwacht table from a previous agent instance (crash recovery).
	// AddTable is idempotent if the table already exists, but stale rules from a
	// previous agent would accumulate. DelTable + Flush first ensures a clean slate.
	conn.DelTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "leitwacht",
	})
	_ = conn.Flush() // ignore error — table may not exist

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "leitwacht",
	})

	chain := conn.AddChain(&nftables.Chain{
		Name:     "dns_redirect",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
	})

	// Accept packets marked by the proxy's upstream socket (prevents redirect loop).
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binary.NativeEndian.AppendUint32(nil, agentMark),
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	dnsRedirectExprs := func(proto byte) []expr.Any {
		return []expr.Any{
			// Match L4 protocol
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{proto},
			},
			// Match destination port == 53
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // destination port offset
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x00, 0x35}, // port 53 in network byte order
			},
			// Load redirect port into register, then redirect
			&expr.Immediate{
				Register: 1,
				Data:     []byte{0x3B, 0xF9}, // port 15353 in network byte order
			},
			&expr.Redir{
				RegisterProtoMin: 1,
			},
		}
	}

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: dnsRedirectExprs(unix.IPPROTO_UDP),
	})

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: dnsRedirectExprs(unix.IPPROTO_TCP),
	})

	addEmbeddedResolverGuard(conn, table)

	err := conn.Flush()
	if err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}

	return nil
}

// dockerResolverIP is Docker's embedded resolver address. It listens on a
// random high port inside every container netns (the well-known :53 is a
// DNAT the job's own resolver traverses), and the loopback allow in the
// egress program would otherwise let a job query it directly, bypassing the
// proxy.
var dockerResolverIP = []byte{127, 0, 0, 11}

// addEmbeddedResolverGuard drops any locally-generated packet destined to
// 127.0.0.11 that does not carry agentMark.
//
// The chain sits at the default filter priority, AFTER the dns_redirect NAT
// chain (dstnat, -100). Ordinary port-53 lookups to 127.0.0.11 have already
// been rewritten to 127.0.0.1:15353 by then and no longer match; the proxy's
// own upstream socket is SO_MARKed with agentMark and is accepted. What
// remains (any other port) is a direct, unproxied query and is dropped.
// Placing it before NAT would drop the redirectable port-53 lookups too.
//
// Docker does not expose an IPv6 embedded resolver by default and the egress
// path is IPv4-only, so there is no ip6 equivalent. A container holding
// CAP_NET_ADMIN can still set SO_MARK itself and bypass this (and the
// redirect); see docs/EVENT_FLOW.md.
func addEmbeddedResolverGuard(conn *nftables.Conn, table *nftables.Table) {
	policyAccept := nftables.ChainPolicyAccept

	chain := conn.AddChain(&nftables.Chain{
		Name:     "docker_dns_guard",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policyAccept,
	})

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// Marked traffic (the proxy's upstream) is allowed.
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binary.NativeEndian.AppendUint32(nil, agentMark),
			},
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// ip daddr 127.0.0.11 (any protocol, any port) -> drop.
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, // IPv4 destination address
				Len:          4,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dockerResolverIP},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})
}

// removeDNSRedirect removes the leitwacht nftables table.
// Safe to call even if the table does not exist (e.g., container netns already gone).
func removeDNSRedirect(conn *nftables.Conn) error {
	conn.DelTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "leitwacht",
	})

	err := conn.Flush()
	if err != nil {
		// Table may not exist — that's fine.
		return nil //nolint:nilerr // table-not-found is expected when container netns is already gone
	}

	return nil
}
