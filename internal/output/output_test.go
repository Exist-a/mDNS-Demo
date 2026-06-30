package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"mdnsscan/internal/banner"
)

func sampleQDiscover() banner.ServiceBanner {
	return banner.ServiceBanner{
		Service:  "_qdiscover._tcp.local",
		Port:     5000,
		Name:     "slw-nas",
		IPv4:     "192.168.1.100",
		IPv6:     "fe80::265e:beff:fe69:a313",
		Hostname: "slw-nas.local",
		TTL:      10,
		// qdiscover 六字段(严格对齐题目示例)
		AccessType:   "https",
		AccessPort:   "86",
		Model:        "TS-X64",
		DisplayModel: "TS-464C",
		FwVer:        "5.2.9",
		FwBuildNum:   "20260214",
	}
}

func sampleHTTP() banner.ServiceBanner {
	return banner.ServiceBanner{
		Service:  "_http._tcp.local",
		Port:     5000,
		Name:     "slw-nas",
		IPv4:     "192.168.1.100",
		IPv6:     "fe80::265e:beff:fe69:a313",
		Hostname: "slw-nas.local",
		TTL:      10,
		Path:     "/",
	}
}

func TestWriteYAML_Structure(t *testing.T) {
	qd, http := sampleQDiscover(), sampleHTTP()
	var buf bytes.Buffer
	if err := WriteYAML(&buf, ScanResult{
		Services: map[string][]banner.ServiceBanner{
			"5000/tcp qdiscover": {qd},
			"5000/tcp http":      {http},
		},
		PTRs: []string{"_qdiscover._tcp.local", "_http._tcp.local", "_qdiscover._tcp.local"},
	}); err != nil {
		t.Fatalf("WriteYAML: %v", err)
	}
	s := buf.String()

	if !strings.Contains(s, "services:") {
		t.Errorf("missing top-level 'services:':\n%s", s)
	}
	if !strings.Contains(s, "answers:") {
		t.Errorf("missing 'answers:' section:\n%s", s)
	}
	if !strings.Contains(s, "answers:\n  PTR:") {
		t.Errorf("missing PTR list:\n%s", s)
	}

	wantFragments := []string{
		"5000/tcp qdiscover:",
		"Name: slw-nas",
		"IPv4: 192.168.1.100",
		"IPv6: fe80::265e:beff:fe69:a313",
		"Hostname: slw-nas.local",
		"TTL: 10",
		"accessType: https",
		"accessPort: \"86\"", // 数字字符串需引号
		"model: TS-X64",
		"displayModel: TS-464C",
		"fwVer: 5.2.9",
		"fwBuildNum: \"20260214\"",
		"5000/tcp http:",
		"path: /",
		"- _qdiscover._tcp.local",
		"- _http._tcp.local",
	}
	for _, frag := range wantFragments {
		if !strings.Contains(s, frag) {
			t.Errorf("missing fragment %q in:\n%s", frag, s)
		}
	}
}

func TestWriteYAML_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteYAML(&buf, ScanResult{}); err != nil {
		t.Fatalf("WriteYAML empty: %v", err)
	}
	s := buf.String()
	if !strings.Contains(s, "services:") || !strings.Contains(s, "answers:") {
		t.Errorf("empty must still have top-level keys:\n%s", s)
	}
}

func TestWriteYAML_NoHostFields_NoNoise(t *testing.T) {
	// 只服务类型,没有 IP 等;不应出现 "IPv4:" 空值
	e := banner.ServiceBanner{Service: "_smb._tcp.local", Port: 445, Name: "x"}
	var buf bytes.Buffer
	if err := WriteYAML(&buf, ScanResult{
		Services: map[string][]banner.ServiceBanner{"445/tcp smb": {e}},
	}); err != nil {
		t.Fatalf("WriteYAML: %v", err)
	}
	s := buf.String()
	if strings.Contains(s, "IPv4:") {
		t.Errorf("should omit empty IPv4:\n%s", s)
	}
}

func TestShortServiceName(t *testing.T) {
	tests := map[string]string{
		"_qdiscover._tcp.local": "qdiscover",
		"_http._tcp.local":      "http",
		"_smb._tcp.local":       "smb",
		"_workstation._tcp.local": "workstation",
		"_device-info._tcp.local": "device-info",
		"_afpovertcp._tcp.local":  "afpovertcp",
		"_foo._udp.local":         "foo",
	}
	for in, want := range tests {
		if got := shortServiceName(in); got != want {
			t.Errorf("shortServiceName(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestWriteJSON_Parseable(t *testing.T) {
	qd, http := sampleQDiscover(), sampleHTTP()
	var buf bytes.Buffer
	if err := WriteJSON(&buf, ScanResult{
		Services: map[string][]banner.ServiceBanner{
			"5000/tcp qdiscover": {qd},
			"5000/tcp http":      {http},
		},
		PTRs: []string{"_qdiscover._tcp.local", "_http._tcp.local", "_qdiscover._tcp.local"},
	}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var got struct {
		Services map[string][]map[string]any `json:"services"`
		Answers  struct {
			PTR []string `json:"PTR"`
		} `json:"answers"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json parse: %v\n%s", err, buf.String())
	}
	arr, ok := got.Services["5000/tcp qdiscover"]
	if !ok || len(arr) != 1 {
		t.Fatalf("missing qdiscover banner in JSON: %+v", got.Services)
	}
	if arr[0]["accessType"] != "https" {
		t.Errorf("JSON accessType=%v", arr[0]["accessType"])
	}
	if arr[0]["fwVer"] != "5.2.9" {
		t.Errorf("JSON fwVer=%v", arr[0]["fwVer"])
	}
	if got.Answers.PTR[0] != "_qdiscover._tcp.local" {
		t.Errorf("JSON PTR[0]=%q", got.Answers.PTR[0])
	}
	if len(got.Answers.PTR) != 2 {
		t.Errorf("PTR dedupe failed: %v", got.Answers.PTR)
	}
	arr2, ok := got.Services["5000/tcp http"]
	if !ok || arr2[0]["path"] != "/" {
		t.Errorf("missing http path in JSON: %+v", arr2)
	}
}

func TestWriteJSON_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, ScanResult{}); err != nil {
		t.Fatalf("WriteJSON empty: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := got["services"]; !ok {
		t.Errorf("empty JSON missing services key")
	}
	if _, ok := got["answers"]; !ok {
		t.Errorf("empty JSON missing answers key")
	}
}
