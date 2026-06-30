// Package mdns 实现基于 RFC 6762 的主动单播探测 + worker pool。
//
// 设计要点:
//   - 对每个 (IP × Port) 用 UDP 单播发送一次 QU-bit query,
//     读响应直到超时或拿到完整 answer+extra
//   - worker pool 控制并发,channel 缓冲降低锁竞争
//   - 单个响应按 service instance 合并 PTR/SRV/TXT/A/AAAA,
//     生成 banner.ServiceBanner 经 channel 返回
package mdns

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"mdnsscan/internal/banner"
)

// ServicesDNSSD 是 RFC 6763 §4 推荐的"枚举所有 service" 查询名。
const ServicesDNSSD = "_services._dns-sd._udp.local."

// ProbeRequest 描述一次扫描任务的输入。
type ProbeRequest struct {
	IPs     []net.IP
	Ports   []uint16
	Timeout time.Duration
	Workers int
}

// ProbeResponse 是 worker 产出的中性结果(包含源 IP/Port,便于上层聚合)。
type ProbeResponse struct {
	IP     net.IP
	Port   uint16
	Banner banner.ServiceBanner
	Err    error
}

// Probe 按 worker pool 模式对 (IP × Port) 笛卡尔积发起主动 mDNS 查询,
// 返回的 channel 在所有 worker 退出后自动关闭。
func Probe(ctx context.Context, req ProbeRequest) <-chan ProbeResponse {
	out := make(chan ProbeResponse)

	workers := req.Workers
	if workers < 1 {
		workers = 1
	}

	type job struct{ ip net.IP }
	jobs := make(chan job)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				for _, port := range req.Ports {
					if ctx.Err() != nil {
						return
					}
					for r := range probeOne(ctx, j.ip, port, req.Timeout) {
						select {
						case <-ctx.Done():
							return
						case out <- r:
						}
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ip := range req.IPs {
			select {
			case <-ctx.Done():
				return
			case jobs <- job{ip: ip}:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// probeOne 对单一 (IP, Port) 发起一次 active mDNS 查询,返回结果 channel。
// 不可达/超时的目标返回空 channel(不报 Err,由 caller 通过结果数推断)。
// 内部用 context 兜底硬超时,避免 OS UDP 抖动把总耗时撑大。
func probeOne(ctx context.Context, ip net.IP, port uint16, timeout time.Duration) <-chan ProbeResponse {
	out := make(chan ProbeResponse, 8)
	target := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))

	go func() {
		defer close(out)

		// 硬上限:连接 + 单次 Read,超出即结束 goroutine
		pctx, pcancel := context.WithTimeout(ctx, timeout+500*time.Millisecond)
		defer pcancel()

		conn, err := net.DialTimeout("udp", target, timeout)
		if err != nil {
			return
		}
		defer conn.Close()

		// RFC 6762 §5.4: 在 QU bit 置位时,mDNS responder 应走 unicast 响应。
		msg := new(dns.Msg)
		msg.SetQuestion(ServicesDNSSD, dns.TypePTR)
		if len(msg.Question) > 0 {
			msg.Question[0].Qclass = dns.ClassINET | 0x8000
		}
		packed, err := msg.Pack()
		if err != nil {
			return
		}
		// 单次绝对 deadline,跨 write/read 复用(避免每次 reset 延后上限)
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if _, err := conn.Write(packed); err != nil {
			return
		}

		// service instance name -> ServiceEntry 累积
		agg := newAggregator()

		buf := make([]byte, 4096)
		for pctx.Err() == nil {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			resp := new(dns.Msg)
			if err := resp.Unpack(buf[:n]); err != nil {
				break
			}
			for _, rr := range resp.Answer {
				agg.absorb(rr)
			}
			for _, rr := range resp.Extra {
				agg.absorb(rr)
			}
			if agg.haveFullEntry() {
				break
			}
		}
		for _, b := range agg.flush(ip, port) {
			select {
			case <-pctx.Done():
				return
			case out <- b:
			}
		}
	}()

	return out
}

// aggregator 按 service instance name 合并 DNS 记录为 banner.ServiceEntry。
type aggregator struct {
	entries map[string]*banner.ServiceEntry
}

func newAggregator() *aggregator {
	return &aggregator{entries: make(map[string]*banner.ServiceEntry)}
}

func (a *aggregator) get(name string) *banner.ServiceEntry {
	n := strings.TrimSuffix(name, ".")
	if _, ok := a.entries[n]; !ok {
		a.entries[n] = &banner.ServiceEntry{}
	}
	return a.entries[n]
}

func (a *aggregator) absorb(rr dns.RR) {
	name := strings.TrimSuffix(rr.Header().Name, ".")
	switch v := rr.(type) {
	case *dns.PTR:
		// PTR.Hdr.Name = service type (例: "_services._dns-sd._udp.local.")
		// v.Ptr         = instance FQDN (例: "slw-nas._qdiscover._tcp.local.")
		inst := strings.TrimSuffix(v.Ptr, ".")
		e := a.get(inst)
		if dot := strings.Index(inst, "."); dot > 0 {
			e.Name = inst[:dot]
			e.ServiceName = inst[dot+1:]
		} else {
			e.ServiceName = inst
		}
		e.TTL = v.Hdr.Ttl
	case *dns.SRV:
		e := a.get(name)
		e.Port = uint16(v.Port)
		if e.HostName == "" {
			e.HostName = strings.TrimSuffix(v.Target, ".")
		}
		e.TTL = v.Hdr.Ttl
	case *dns.TXT:
		e := a.get(name)
		e.Text = append(e.Text, v.Txt...)
		e.TTL = v.Hdr.Ttl
	case *dns.A:
		e := a.get(name)
		e.AddrIPv4 = v.A
		e.TTL = v.Hdr.Ttl
	case *dns.AAAA:
		e := a.get(name)
		e.AddrIPv6 = v.AAAA
		e.TTL = v.Hdr.Ttl
	}
}

// haveFullEntry 当至少有一个 entry 拿到 SRV+IPv4 时返回 true,触发退出。
func (a *aggregator) haveFullEntry() bool {
	for _, e := range a.entries {
		if e.Port > 0 && e.AddrIPv4 != nil {
			return true
		}
	}
	return false
}

func (a *aggregator) flush(ip net.IP, port uint16) []ProbeResponse {
	// Step 1: 把 hostname-only entry 收集成 IPv4/IPv6 lookup,供 service instance 继承。
	hostIPv4 := map[string]net.IP{}
	hostIPv6 := map[string]net.IP{}
	for rawName, e := range a.entries {
		n := strings.TrimSuffix(rawName, ".")
		if e.AddrIPv4 != nil {
			hostIPv4[n] = e.AddrIPv4
		}
		if e.AddrIPv6 != nil {
			hostIPv6[n] = e.AddrIPv6
		}
	}

	var out []ProbeResponse
	for instName, e := range a.entries {
		if e.ServiceName == "" {
			continue
		}
		if e.Name == "" {
			// 从 instance FQDN 拆 name
			if dot := strings.Index(instName, "."); dot > 0 {
				e.Name = instName[:dot]
			}
		}
		// 从 hostname-only entry 继承 IP(典型 mDNS:host A 记录单独出现一次)
		if e.AddrIPv4 == nil {
			if v4, ok := hostIPv4[e.HostName]; ok {
				e.AddrIPv4 = v4
			}
		}
		if e.AddrIPv6 == nil {
			if v6, ok := hostIPv6[e.HostName]; ok {
				e.AddrIPv6 = v6
			}
		}
		out = append(out, ProbeResponse{
			IP:     ip,
			Port:   port,
			Banner: banner.ParseEntry(*e),
		})
	}
	return out
}
