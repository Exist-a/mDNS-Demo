package e2e

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mdnsscan/internal/banner"
	"mdnsscan/internal/mdns"
	"mdnsscan/internal/output"
)

// TestE2E_EmitExamples 把 YAML 和 JSON 样本同时输出到 ../out/ 目录,
// 供外部 Python 脚本 (scripts/validate_yaml.py, validate_json.py) 解析,
// 验证 spec.md "Scenario: YAML 默认输出 / JSON 切换" 的可解析性。
func TestE2E_EmitExamples(t *testing.T) {
	port, stop := startFakeMDNS(t, fakeQDiscoverHandler)
	defer stop()

	dir := filepath.Join("..", "out")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	yamlOut := filepath.Join(dir, "example.yaml")
	jsonOut := filepath.Join(dir, "example.json")

	services, ptrs := collectPipeline(t, port)

	var ybuf bytes.Buffer
	if err := output.WriteYAML(&ybuf, output.ScanResult{Services: services, PTRs: ptrs}); err != nil {
		t.Fatalf("WriteYAML: %v", err)
	}
	if err := os.WriteFile(yamlOut, ybuf.Bytes(), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	t.Logf("yaml: %s (%d bytes)", yamlOut, ybuf.Len())

	var jbuf bytes.Buffer
	if err := output.WriteJSON(&jbuf, output.ScanResult{Services: services, PTRs: ptrs}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if err := os.WriteFile(jsonOut, jbuf.Bytes(), 0o644); err != nil {
		t.Fatalf("write json: %v", err)
	}
	t.Logf("json: %s (%d bytes)", jsonOut, jbuf.Len())
}

// collectPipeline 是 collectAndRender 的解耦版:返回 services + ptrs,
// 供 YAML/JSON 两种 renderer 共用。
func collectPipeline(t *testing.T, port int) (map[string][]banner.ServiceBanner, []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	results := mdns.Probe(ctx, mdns.ProbeRequest{
		IPs:     []net.IP{net.ParseIP("127.0.0.1")},
		Ports:   []uint16{uint16(port)},
		Timeout: 500 * time.Millisecond,
		Workers: 1,
	})

	services := map[string][]banner.ServiceBanner{}
	seen := map[string]bool{}
	var ptrs []string
	for r := range results {
		if r.Err != nil {
			continue
		}
		b := r.Banner
		if b.Service == "" {
			continue
		}
		key := output.ServiceKey(b)
		services[key] = append(services[key], b)
		if !seen[b.Service] {
			seen[b.Service] = true
			ptrs = append(ptrs, b.Service)
		}
	}
	return services, ptrs
}
