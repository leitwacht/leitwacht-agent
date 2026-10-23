package enforcer

import (
	"log/slog"
	"net"
	"reflect"
	"testing"
)

func TestSeedAllowMapPorts(t *testing.T) {
	tests := []struct {
		name  string
		ports []int
		want  [][]int
	}{
		{"all out of range", []int{65979}, nil},
		{"mixed", []int{443, 65536}, [][]int{{443}}},
		{"nil defaults", nil, [][]int{{443, 80}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got [][]int

			cfg := &DNSProxyConfig{
				Logger: slog.Default(),
				AddToAllowMap: func(_ net.IP, ports []int, _ uint32) error {
					got = append(got, ports)

					return nil
				},
			}

			seedAllowMap(cfg, []string{"192.0.2.1"}, tc.ports, 0)

			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("AddToAllowMap calls = %v, want %v", got, tc.want)
			}
		})
	}
}
