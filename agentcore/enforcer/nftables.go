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

	err := conn.Flush()
	if err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}

	return nil
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
