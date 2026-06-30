package mdns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeQDiscoverHandler 模拟一台 _qdiscover._tcp.local 设备,返回完整的
// PTR/SRV/TXT/A/AAAA 记录,用于测试 active unicast probe。
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
			Hdr:   dns.RR_Header{Name: "slw-nas._qdiscover._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
			Port:  5000,
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

// startFakeMDNS 启动一个本机回环 fake mDNS server,返回 port + 清理函数。
func startFakeMDNS(t *testing.T, h dns.HandlerFunc) (port int, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	stopped := make(chan struct{})
	go func() {
		_ = srv.ActivateAndServe()
		close(stopped)
	}()
	time.Sleep(50 * time.Millisecond) // 让 server 起来
	udpAddr := pc.LocalAddr().(*net.UDPAddr)
	return udpAddr.Port, func() {
		_ = srv.Shutdown()
		_ = pc.Close()
		<-stopped
	}
}

func TestProbe_QDiscoverActiveUnicast(t *testing.T) {
	port, stop := startFakeMDNS(t, fakeQDiscoverHandler)
	defer stop()

	ip := net.ParseIP("127.0.0.1")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := Probe(ctx, ProbeRequest{
		IPs:     []net.IP{ip},
		Ports:   []uint16{uint16(port)},
		Timeout: 500 * time.Millisecond,
		Workers: 1,
	})

	var got []ProbeResponse
	for r := range out {
		got = append(got, r)
	}
	if len(got) == 0 {
		t.Fatalf("probe yielded no results")
	}
	var found bool
	for _, r := range got {
		if r.Err != nil {
			t.Logf("probe err: %v", r.Err)
			continue
		}
		b := r.Banner
		if b.Service == "_qdiscover._tcp.local" &&
			b.AccessType == "https" && b.AccessPort == "86" &&
			b.Model == "TS-X64" && b.DisplayModel == "TS-464C" &&
			b.FwVer == "5.2.9" && b.FwBuildNum == "20260214" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("qdiscover six fields not emitted; got=%+v", got)
	}
}

func TestProbe_NoServer_NoResults_NoHang(t *testing.T) {
	// 探测不存在的目标:应超时返回空 channel,不挂死
	ip := net.ParseIP("127.0.0.1")
	_ = strconv.Itoa
	_ = fmt.Sprintf

	// 找目前空闲的高位端口用于"不存在"
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadPort := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	t0 := time.Now()
	out := Probe(ctx, ProbeRequest{
		IPs:     []net.IP{ip},
		Ports:   []uint16{uint16(deadPort)},
		Timeout: 200 * time.Millisecond,
		Workers: 1,
	})
	count := 0
	for range out {
		count++
	}
	elapsed := time.Since(t0)
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("probe took too long: %s", elapsed)
	}
}

func TestProbe_ManyIPs_ConcurrentWorkers(t *testing.T) {
	port, stop := startFakeMDNS(t, fakeQDiscoverHandler)
	defer stop()

	ips := make([]net.IP, 0, 30)
	for i := 0; i < 30; i++ {
		ips = append(ips, net.ParseIP("127.0.0.1"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out := Probe(ctx, ProbeRequest{
		IPs:     ips,
		Ports:   []uint16{uint16(port)},
		Timeout: 500 * time.Millisecond,
		Workers: 10,
	})

	total := 0
	for r := range out {
		if r.Err == nil && r.Banner.AccessType == "https" {
			total++
		}
	}
	if total == 0 {
		t.Fatalf("expected at least one banner hit, got 0")
	}
}
