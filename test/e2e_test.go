// Package e2e 端到端集成测试:fake mDNS 服务器 → probe → banner → output 全链路。
//
// 这里直接走内部包(MDAN/Output),不通过 cmd/mdnsscan 子进程,
// 子进程级烟测在 cmd/mdnsscan/main_test.go。
package e2e

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mdnsscan/internal/banner"
	"mdnsscan/internal/mdns"
	"mdnsscan/internal/output"
)

// fakeQDiscoverHandler 与 internal/mdns/probe_test.go 一致,作为单源真相。
func fakeQDiscoverHandler(w dns.ResponseWriter, r *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true
	if len(r.Question) == 0 {
		_ = w.WriteMsg(resp)
		return
	}
	q := r.Question[0]
	if q.Name != "_services._dns-sd._udp.local." {
		_ = w.WriteMsg(resp)
		return
	}
	resp.Answer = []dns.RR{
		&dns.PTR{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
			Ptr: "slw-nas._qdiscover._tcp.local.",
		},
	}
	resp.Extra = []dns.RR{
		&dns.SRV{
			Hdr:    dns.RR_Header{Name: "slw-nas._qdiscover._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
			Port:   5000,
			Target: "slw-nas.local.",
		},
		&dns.TXT{
			Hdr: dns.RR_Header{Name: "slw-nas._qdiscover._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
			Txt: []string{
				"accessType=https",
				"accessPort=86",
				"model=TS-X64",
				"displayModel=TS-464C",
				"fwVer=5.2.9",
				"fwBuildNum=20260214",
			},
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
			A:   net.ParseIP("192.168.1.100").To4(),
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 10},
			AAAA: net.ParseIP("fe80::265e:beff:fe69:a313"),
		},
	}
	_ = w.WriteMsg(resp)
}

// startFakeMDNS 启动一台本机 fake mDNS,返回端口。
func startFakeMDNS(t *testing.T, h dns.HandlerFunc) (port int, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	stopped := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go func() {
		_ = srv.ActivateAndServe()
		close(stopped)
	}()
	time.Sleep(50 * time.Millisecond)
	udpAddr := pc.LocalAddr().(*net.UDPAddr)
	return udpAddr.Port, func() {
		_ = srv.Shutdown()
		_ = pc.Close()
		<-stopped
	}
}

// collectAndRender 走 mdns.Probe → banner → output.WriteYAML 全链路。
func collectAndRender(t *testing.T, port int) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := mdns.Probe(ctx, mdns.ProbeRequest{
		IPs:     []net.IP{net.ParseIP("127.0.0.1")},
		Ports:   []uint16{uint16(port)},
		Timeout: 500 * time.Millisecond,
		Workers: 1,
	})

	services := map[string][]banner.ServiceBanner{}
	seen := map[string]bool{}
	var ptrs []string
	for r := range out {
		if r.Err != nil {
			t.Logf("probe err: %v", r.Err)
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

	var buf bytes.Buffer
	if err := output.WriteYAML(&buf, output.ScanResult{Services: services, PTRs: ptrs}); err != nil {
		t.Fatalf("WriteYAML: %v", err)
	}
	return buf.String()
}

func TestE2E_QDiscoverPipeline_YAML(t *testing.T) {
	port, stop := startFakeMDNS(t, fakeQDiscoverHandler)
	defer stop()

	s := collectAndRender(t, port)

	required := []string{
		"services:",
		"5000/tcp qdiscover:",
		"Name: slw-nas",
		"IPv4: 192.168.1.100",
		"IPv6: fe80::265e:beff:fe69:a313",
		"Hostname: slw-nas.local",
		"TTL: 10",
		"accessType: https",
		`accessPort: "86"`,
		"model: TS-X64",
		"displayModel: TS-464C",
		"fwVer: 5.2.9",
		`fwBuildNum: "20260214"`,
		"answers:",
		"  PTR:",
		"- _qdiscover._tcp.local",
	}
	for _, frag := range required {
		if !strings.Contains(s, frag) {
			t.Errorf("missing fragment %q in YAML:\n%s", frag, s)
		}
	}
}
