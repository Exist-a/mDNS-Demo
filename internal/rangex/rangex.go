// Package rangex 提供 CIDR 展开与端口范围解析。
//
// Skeleton: API 形状已定,具体边界行为 (空 CIDR、IPv6、wildcard 等)
// 在 Tasks 2 的 TDD 步骤中以测试驱动补全。
package rangex

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ExpandCIDRs 解析逗号分隔的 CIDR 列表,返回全部主机 IP。
// 当前仅支持 IPv4。
func ExpandCIDRs(spec string) ([]net.IP, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, fmt.Errorf("empty CIDR spec")
	}
	var out []net.IP
	for _, raw := range strings.Split(spec, ",") {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		if ip.To4() == nil {
			return nil, fmt.Errorf("only IPv4 CIDR supported: %q", s)
		}
		for cur := ip.Mask(ipNet.Mask); ipNet.Contains(cur); incIP(cur) {
			cp := append(net.IP(nil), cur...)
			out = append(out, cp)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no IPs resolved from %q", spec)
	}
	return out, nil
}

// ParsePorts 解析端口表达式,支持 5353 / 1-1024 / 1-1024,5353,8000-8100。
func ParsePorts(spec string) ([]uint16, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, fmt.Errorf("empty ports spec")
	}
	var out []uint16
	for _, tok := range strings.Split(spec, ",") {
		t := strings.TrimSpace(tok)
		if t == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(t, "-"); ok {
			l, err := strconv.Atoi(strings.TrimSpace(lo))
			if err != nil || l < 1 || l > 65535 {
				return nil, fmt.Errorf("invalid port range %q", t)
			}
			r, err := strconv.Atoi(strings.TrimSpace(hi))
			if err != nil || r < 1 || r > 65535 || r < l {
				return nil, fmt.Errorf("invalid port range %q", t)
			}
			for p := l; p <= r; p++ {
				out = append(out, uint16(p))
			}
			continue
		}
		p, err := strconv.Atoi(t)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", t)
		}
		out = append(out, uint16(p))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports parsed from %q", spec)
	}
	return out, nil
}

// incIP 原地递增 net.IP (按大端)。
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			return
		}
	}
}
