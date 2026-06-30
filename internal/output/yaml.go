// Package output 把 ProbeResponse 渲染为 YAML / JSON。
//
// 输出 schema(顶层):
//   services:  "<port>/tcp <shortService>": [{Name, IPv4, IPv6, Hostname, TTL, ...deep}]
//   answers:
//     PTR:     [...]
//
// 字段顺序与题目示例严格对齐;深层字段(按 service type) 追加在最小五字段后。
package output

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"mdnsscan/internal/banner"
)

// ScanResult 是 CLI 最终输出的中性结构。
//
// Services 的 map key 推荐用 ServiceKey(banner.ServiceBanner) 生成
// "<port>/tcp <shortService>" 形式(如 "5000/tcp qdiscover")。
type ScanResult struct {
	Services map[string][]banner.ServiceBanner
	PTRs     []string
}

// ServiceKey 返回题目示例风格的 service key。
func ServiceKey(b banner.ServiceBanner) string {
	return fmt.Sprintf("%d/tcp %s", b.Port, shortServiceName(b.Service))
}

// shortServiceName 把 service type 截短成题目示例中的短名。
//
//	"_qdiscover._tcp.local" → "qdiscover"
//	"_device-info._tcp.local" → "device-info"
//	"_foo._udp.local" → "foo"
func shortServiceName(svc string) string {
	svc = strings.TrimSuffix(svc, ".")
	svc = strings.TrimPrefix(svc, "_")
	for _, suf := range []string{"._tcp.local", "._udp.local"} {
		if strings.HasSuffix(svc, suf) {
			return strings.TrimSuffix(svc, suf)
		}
	}
	return svc
}

// WriteYAML 输出题目示例结构的 YAML。
//
// 排序:先按 service key,后按 banner 在数组里的出现顺序(保持探测顺序)。
func WriteYAML(w io.Writer, r ScanResult) error {
	keys := make([]string, 0, len(r.Services))
	for k := range r.Services {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	if _, err := io.WriteString(w, "services:\n"); err != nil {
		return err
	}
	for _, k := range keys {
		if _, err := fmt.Fprintf(w, "  %s:\n", k); err != nil {
			return err
		}
		for _, b := range r.Services[k] {
			writeBanner(w, b)
		}
	}

	if _, err := io.WriteString(w, "answers:\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "  PTR:\n"); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, p := range dedupPTRs(r.PTRs) {
		if seen[p] {
			continue
		}
		seen[p] = true
		if _, err := fmt.Fprintf(w, "    - %s\n", p); err != nil {
			return err
		}
	}
	return nil
}

// writeBanner 把单个 banner 按题目示例字段顺序输出(空值省略)。
func writeBanner(w io.Writer, b banner.ServiceBanner) {
	if b.Name != "" {
		fmt.Fprintf(w, "    Name: %s\n", b.Name)
	}
	if b.IPv4 != "" {
		fmt.Fprintf(w, "    IPv4: %s\n", b.IPv4)
	}
	if b.IPv6 != "" {
		fmt.Fprintf(w, "    IPv6: %s\n", b.IPv6)
	}
	if b.Hostname != "" {
		fmt.Fprintf(w, "    Hostname: %s\n", b.Hostname)
	}
	if b.TTL > 0 {
		fmt.Fprintf(w, "    TTL: %d\n", b.TTL)
	}
	// 深度字段(按 service type)
	if b.Path != "" {
		fmt.Fprintf(w, "    path: %s\n", b.Path)
	}
	if b.AccessType != "" {
		fmt.Fprintf(w, "    accessType: %s\n", b.AccessType)
	}
	if b.AccessPort != "" {
		fmt.Fprintf(w, "    accessPort: %s\n", yamlQuote(b.AccessPort))
	}
	if b.Model != "" {
		fmt.Fprintf(w, "    model: %s\n", b.Model)
	}
	if b.DisplayModel != "" {
		fmt.Fprintf(w, "    displayModel: %s\n", b.DisplayModel)
	}
	if b.FwVer != "" {
		fmt.Fprintf(w, "    fwVer: %s\n", b.FwVer)
	}
	if b.FwBuildNum != "" {
		fmt.Fprintf(w, "    fwBuildNum: %s\n", yamlQuote(b.FwBuildNum))
	}
}

// yamlQuote 对可能引起 YAML 解析歧义的字符串加双引号。
//
// 下列情况必加双引号:
//   - 纯数字字符串(避免 YAML 解析为 int/float,丢失原始语义)
//   - 含特殊字符 ":" "#" "\n" "'" "\"" 或首尾空格的
func yamlQuote(s string) string {
	if s == "" {
		return s
	}
	if looksLikeNumber(s) || strings.ContainsAny(s, ":#\n\"'") || strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") {
		return fmt.Sprintf("%q", s)
	}
	return s
}

// looksLikeNumber 用 strconv.ParseFloat 判断是否会被 YAML 解析为数字。
func looksLikeNumber(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// dedupPTRs 保留首次出现顺序去重 PTR 列表。
func dedupPTRs(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, p := range in {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
