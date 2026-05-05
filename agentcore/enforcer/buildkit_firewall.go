//go:build linux

package enforcer

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// buildkitFirewallTable is the nftables table that hosts the input-filter chain
// protecting the BuildKit DNS proxy from off-host queriers.
const (
	buildkitFirewallTable = "leitwacht_buildkit_dns"
	buildkitFirewallChain = "input_filter"

	// Rule-expression constants (IPv4 header layout + nftables width defaults).
	ipv4DstOffset = 16 // byte offset of dst-address inside the IPv4 header
	ipv4AddrLen   = 4
	ifnameSize    = 16 // IFNAMSIZ — nftables IIFNAME match width
)

// dnsPort is the well-known port for DNS; kept separate from the ints above
// so the uint16 network-byte-order encoding via binary.BigEndian is explicit.
const dnsPort uint16 = 53

// firewallInstaller abstracts the kernel-facing half of setupBuildkitDNSFirewall
// so tests can exercise the skip-loopback branch without root/netlink. The real
// implementation lives in nftablesFirewallInstaller below.
type firewallInstaller interface {
	install(listenIP net.IP) error
	remove() error
}

// setupBuildkitDNSFirewall installs host-netns nftables rules that drop all
// non-loopback traffic destined for the BuildKit DNS proxy's listen IP on
// port 53 (udp + tcp).
//
// The firewall is ONLY needed when the proxy is reachable from off-host — a
// routable bind address turns the proxy into an open resolver that (a) can be
// abused for DNS amplification, and (b) lets an attacker populate the agent's
// eBPF allow map via resolved IPs for allowlisted domains, punching policy
// holes. For loopback/unspecified binds the rules are unnecessary and we
// return nil without touching nftables.
//
// Callers should treat any error as fatal (fail-closed): better to crash
// the agent than to run with an exposed resolver.
func setupBuildkitDNSFirewall(conn *nftables.Conn, listenIP net.IP, logger *slog.Logger) error {
	return setupBuildkitDNSFirewallWith(&nftablesFirewallInstaller{conn: conn}, listenIP, logger)
}

// removeBuildkitDNSFirewall tears down the table installed by
// setupBuildkitDNSFirewall. Safe to call if the table was never installed.
func removeBuildkitDNSFirewall(conn *nftables.Conn) error {
	return (&nftablesFirewallInstaller{conn: conn}).remove()
}

// setupBuildkitDNSFirewallWith is the test seam: accepts any firewallInstaller
// so unit tests can observe whether the skip-loopback branch fires without
// actually talking to netlink.
func setupBuildkitDNSFirewallWith(inst firewallInstaller, listenIP net.IP, logger *slog.Logger) error {
	if isLoopbackOrUnspecified(listenIP) {
		logger.Info("buildkit dns firewall skipped (loopback/unspecified bind)",
			"listen_ip", listenIP.String(),
		)

		return nil
	}

	err := inst.install(listenIP)
	if err != nil {
		return fmt.Errorf("install buildkit dns firewall: %w", err)
	}

	logger.Info("buildkit dns firewall installed", "listen_ip", listenIP.String())

	return nil
}

// isLoopbackOrUnspecified returns true for 127.0.0.0/8 and 0.0.0.0 binds —
// both are unreachable from off-host, so the firewall is redundant.
func isLoopbackOrUnspecified(ip net.IP) bool {
	if ip == nil {
		return true
	}

	return ip.IsLoopback() || ip.IsUnspecified()
}

// buildkitDNSFirewallRules constructs the table, chain, and rule set for the
// BuildKit DNS firewall. Pulled out of setupBuildkitDNSFirewall so tests can
// assert the generated nftables expressions without touching the kernel.
func buildkitDNSFirewallRules(listenIP net.IP) (*nftables.Table, *nftables.Chain, []*nftables.Rule) {
	priority := *nftables.ChainPriorityRef(-100)

	table := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   buildkitFirewallTable,
	}

	chain := &nftables.Chain{
		Name:     buildkitFirewallChain,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &priority,
	}

	ipv4 := listenIP.To4()

	rules := []*nftables.Rule{
		{
			// iif "lo" accept — always allow loopback (locally-originated queries).
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     ifname("lo"),
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		},
		{
			// ip daddr <listenIP> udp dport 53 counter drop
			Table: table,
			Chain: chain,
			Exprs: dropDNSExprs(ipv4, unix.IPPROTO_UDP),
		},
		{
			// ip daddr <listenIP> tcp dport 53 counter drop
			Table: table,
			Chain: chain,
			Exprs: dropDNSExprs(ipv4, unix.IPPROTO_TCP),
		},
	}

	return table, chain, rules
}

// dropDNSExprs builds expressions matching "ip daddr <ip> <proto> dport 53"
// followed by counter + drop.
func dropDNSExprs(ipv4 net.IP, proto byte) []expr.Any {
	return []expr.Any{
		// Match destination IP (offset 16 in the IPv4 header, 4 bytes).
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       ipv4DstOffset,
			Len:          ipv4AddrLen,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ipv4,
		},
		// Match L4 proto.
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{proto},
		},
		// Match destination port 53.
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binary.BigEndian.AppendUint16(nil, dnsPort),
		},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// ifname pads an interface name to IFNAMSIZ (16 bytes, NUL-terminated) —
// the fixed size nftables expects for ifname comparisons.
func ifname(name string) []byte {
	buf := make([]byte, ifnameSize)
	copy(buf, name)

	return buf
}

// nftablesFirewallInstaller talks to the kernel via netlink. It's the real
// firewallInstaller used in production.
type nftablesFirewallInstaller struct {
	conn *nftables.Conn
}

func (n *nftablesFirewallInstaller) install(listenIP net.IP) error {
	// Clean up any stale table from a previous agent instance (crash recovery),
	// matching setupDNSRedirect's idempotent pattern.
	n.conn.DelTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   buildkitFirewallTable,
	})
	_ = n.conn.Flush() // ignore error — table may not exist

	table, chain, rules := buildkitDNSFirewallRules(listenIP)

	n.conn.AddTable(table)
	n.conn.AddChain(chain)

	for _, r := range rules {
		n.conn.AddRule(r)
	}

	err := n.conn.Flush()
	if err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}

	return nil
}

func (n *nftablesFirewallInstaller) remove() error {
	n.conn.DelTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   buildkitFirewallTable,
	})

	err := n.conn.Flush()
	if err != nil {
		// Table may not exist — that's fine.
		return nil //nolint:nilerr // table-not-found is expected when we never installed
	}

	return nil
}
