package rangex

import (
	"strings"
	"testing"
)

func TestExpandCIDRs(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []string
		wantErr string
	}{
		{
			name: "single IPv4 /30",
			spec: "192.168.1.0/30",
			want: []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"},
		},
		{
			name: "single host /32",
			spec: "10.0.0.5/32",
			want: []string{"10.0.0.5"},
		},
		{
			name: "multiple CIDRs comma",
			spec: "192.168.1.0/30,10.0.0.5/32",
			want: []string{
				"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3",
				"10.0.0.5",
			},
		},
		{
			name: "whitespace tolerated",
			spec: " 192.168.1.0/30 , 10.0.0.5/32 ",
			want: []string{
				"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3",
				"10.0.0.5",
			},
		},
		{name: "empty", spec: "", wantErr: "empty CIDR spec"},
		{name: "garbage", spec: "not-a-cidr", wantErr: "invalid CIDR"},
		{
			name: "out-of-range host bits",
			// 192.168.1.5/24: host bits != 0,go 会拒绝
			spec: "192.168.1.5/24",
			// standard lib 接受这种形式并把网络地址归一,我们的实现透传即可 — 此处期望成功
			want: nil, // 占位:实际长度不重要,只走成功路径
		},
		{
			name:    "IPv6 unsupported",
			spec:    "fe80::/64",
			wantErr: "IPv4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandCIDRs(tt.spec)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.want == nil {
				return // 仅校验成功路径
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d IPs, want %d (got=%v)", len(got), len(tt.want), got)
			}
			for i, ip := range got {
				if ip.String() != tt.want[i] {
					t.Fatalf("got %s at %d, want %s", ip, i, tt.want[i])
				}
			}
		})
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []uint16
		wantErr string
	}{
		{name: "single", spec: "5353", want: []uint16{5353}},
		{name: "list", spec: "5353,5354", want: []uint16{5353, 5354}},
		{name: "range small", spec: "1-3", want: []uint16{1, 2, 3}},
		{name: "range large ends", spec: "65534-65535", want: []uint16{65534, 65535}},
		{name: "mixed", spec: "1-3,5,8-10", want: []uint16{1, 2, 3, 5, 8, 9, 10}},
		{name: "whitespace", spec: " 1-3 , 5 ", want: []uint16{1, 2, 3, 5}},
		{name: "empty", spec: "", wantErr: "empty ports spec"},
		{name: "zero", spec: "0", wantErr: "invalid port"},
		{name: "out of range high", spec: "65536", wantErr: "invalid port"},
		{name: "reversed range", spec: "10-1", wantErr: "invalid port range"},
		{name: "non-numeric", spec: "foo", wantErr: "invalid port"},
		{name: "non-numeric range", spec: "abc-def", wantErr: "invalid port range"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePorts(tt.spec)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d ports, want %d (got=%v)", len(got), len(tt.want), got)
			}
			for i, p := range got {
				if p != tt.want[i] {
					t.Fatalf("got %d at %d, want %d", p, i, tt.want[i])
				}
			}
		})
	}
}
