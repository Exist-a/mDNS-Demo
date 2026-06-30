package banner

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadFixture 从 testdata/fixtures/ 读取 JSON fixture 转成 ServiceEntry。
func loadFixture(t *testing.T, name string) ServiceEntry {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "fixtures", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var raw struct {
		Service string   `json:"service"`
		Name    string   `json:"name"`
		Host    string   `json:"hostname"`
		IPv4    string   `json:"ipv4"`
		IPv6    string   `json:"ipv6"`
		Port    uint16   `json:"port"`
		TTL     uint32   `json:"ttl"`
		Text    []string `json:"text"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	e := ServiceEntry{
		ServiceName: raw.Service,
		Name:        raw.Name,
		HostName:    raw.Host,
		Port:        raw.Port,
		TTL:         raw.TTL,
		Text:        raw.Text,
	}
	if raw.IPv4 != "" {
		e.AddrIPv4 = net.ParseIP(raw.IPv4)
	}
	if raw.IPv6 != "" {
		e.AddrIPv6 = net.ParseIP(raw.IPv6)
	}
	return e
}

func TestParseEntry_QDiscoverFixture_AllSixFields(t *testing.T) {
	e := loadFixture(t, "qdiscover.json")
	b := ParseEntry(e)

	// 最小 5 字段
	if b.Name != "slw-nas" {
		t.Errorf("Name=%q", b.Name)
	}
	if b.IPv4 == "" {
		t.Errorf("IPv4 empty")
	}
	if b.IPv6 == "" {
		t.Errorf("IPv6 empty")
	}
	if b.Hostname != "slw-nas.local" {
		t.Errorf("Hostname=%q", b.Hostname)
	}
	if b.TTL != 10 {
		t.Errorf("TTL=%d, want 10", b.TTL)
	}
	if b.Port != 5000 {
		t.Errorf("Port=%d, want 5000", b.Port)
	}
	// qdiscover 6 字段(题目示例严格对齐)
	if b.AccessType != "https" {
		t.Errorf("accessType=%q, want https", b.AccessType)
	}
	if b.AccessPort != "86" {
		t.Errorf("accessPort=%q, want 86", b.AccessPort)
	}
	if b.Model != "TS-X64" {
		t.Errorf("model=%q, want TS-X64", b.Model)
	}
	if b.DisplayModel != "TS-464C" {
		t.Errorf("displayModel=%q, want TS-464C", b.DisplayModel)
	}
	if b.FwVer != "5.2.9" {
		t.Errorf("fwVer=%q, want 5.2.9", b.FwVer)
	}
	if b.FwBuildNum != "20260214" {
		t.Errorf("fwBuildNum=%q, want 20260214", b.FwBuildNum)
	}
}

func TestParseEntry_HTTPPathFromFixture(t *testing.T) {
	e := loadFixture(t, "http.json")
	b := ParseEntry(e)
	if b.Path != "/" {
		t.Errorf("Path=%q, want /", b.Path)
	}
}

func TestParseEntry_DeviceInfoModelFromFixture(t *testing.T) {
	e := loadFixture(t, "device-info.json")
	b := ParseEntry(e)
	if b.Model != "Xserve" {
		t.Errorf("Model=%q, want Xserve", b.Model)
	}
}

func TestParseEntry_AFPNameContains(t *testing.T) {
	e := loadFixture(t, "afpovertcp.json")
	b := ParseEntry(e)
	if !strings.Contains(b.Name, "AFP") {
		t.Errorf("Name=%q should contain AFP", b.Name)
	}
}

func TestParseEntry_WorkstationMinimalOnly(t *testing.T) {
	e := loadFixture(t, "workstation.json")
	b := ParseEntry(e)
	if b.Name != "slw-nas" || b.TTL != 10 {
		t.Errorf("basic fields wrong: %+v", b)
	}
	// workstation 不应填深度字段
	if b.AccessType != "" || b.Path != "" || b.Model != "" {
		t.Errorf("workstation should not fill deep fields: %+v", b)
	}
}

func TestParseEntry_SMBMinimalOnly(t *testing.T) {
	e := loadFixture(t, "smb.json")
	b := ParseEntry(e)
	if b.Name != "slw-nas" {
		t.Errorf("Name=%q", b.Name)
	}
}

func TestParseEntry_UnknownService_NoCrash(t *testing.T) {
	e := ServiceEntry{
		ServiceName: "_unknown._tcp.local",
		Name:        "x",
		HostName:    "x.local",
		Text:        []string{"foo=bar", "flag"},
	}
	b := ParseEntry(e)
	if b.Name != "x" {
		t.Errorf("Name=%q", b.Name)
	}
	if b.Path != "" || b.AccessType != "" || b.Model != "" {
		t.Errorf("unknown service should not fill deep fields: %+v", b)
	}
}

func TestParseTXT(t *testing.T) {
	m := ParseTXT([]string{"a=1", "b=2", "flag"})
	if m["a"] != "1" {
		t.Errorf("a=%q", m["a"])
	}
	if m["b"] != "2" {
		t.Errorf("b=%q", m["b"])
	}
	if _, ok := m["flag"]; !ok {
		t.Errorf("flag attr missing")
	}
	if m["flag"] != "" {
		t.Errorf("flag should be empty value, got %q", m["flag"])
	}
}
