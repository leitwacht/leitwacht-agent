package enforcer

import (
	"testing"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// TestCollectIPRulesSkipsOutOfRangePorts guards the uint16 wraparound in
// PackAllowKey: 65979 would otherwise install as 443 and 65536 as 0.
func TestCollectIPRulesSkipsOutOfRangePorts(t *testing.T) {
	for _, port := range []int{65979, 65536, -1} {
		deny, allow := collectIPRules(
			ipRulePolicy("block",
				cidrRule("192.0.2.10", policy.ActionAllow, port),
				cidrRule("192.0.2.11", policy.ActionDeny, port),
			),
			testLogger(),
		)

		if len(deny) != 0 || len(allow) != 0 {
			t.Errorf("port %d: deny=%+v allow=%+v, want none", port, deny, allow)
		}
	}

	_, allow := collectIPRules(
		ipRulePolicy("block", cidrRule("192.0.2.10", policy.ActionAllow, 0, 65535, 70000)),
		testLogger(),
	)
	if len(allow) != 2 {
		t.Fatalf("allow = %+v, want only ports 0 and 65535", allow)
	}
}
