// Package banner 把 mDNS 响应条目解析为深度 ServiceBanner。
//
// Skeleton: 结构定义占位,字段抽取逻辑按
// .trae/specs/mdns-asset-scanner/tasks.md Task 3 实现,并以
// testdata/fixtures/ 下的 FOFA 来源响应作为回归样本。
package banner

import (
	"net"
	"strings"
)

// ServiceEntry 是扫描产出的中性 service 类型,避免 skeleton 阶段耦合
// 到 grandcat/zeroconf 的具体字段(实现期做适配)。
type ServiceEntry struct {
	Name        string   // 例: "slw-nas"
	ServiceName string   // 例: "_qdiscover._tcp.local"
	HostName    string   // 例: "slw-nas.local"
	Port        uint16   // 例: 5000
	TTL         uint32   // 例: 10
	AddrIPv4    net.IP   // 解析后的 IPv4
	AddrIPv6    net.IP   // 解析后的 IPv6
	Text        []string // TXT 记录原始 key=value 数组
}

// ServiceBanner 是单个 service 类型对外暴露的字段集合。
// 字段命名与题目示例 banner 一致(见 spec.md "深度 Banner 识别")。
type ServiceBanner struct {
	Service  string
	Port     uint16
	Name     string
	IPv4     string
	IPv6     string
	Hostname string
	TTL      uint32

	// 深度字段(按 service type 抽取)
	Path         string // _http._tcp.local
	AccessType   string // _qdiscover._tcp.local
	AccessPort   string // _qdiscover._tcp.local
	Model        string // _qdiscover._tcp.local / _device-info._tcp.local
	DisplayModel string // _qdiscover._tcp.local
	FwVer        string // _qdiscover._tcp.local
	FwBuildNum   string // _qdiscover._tcp.local
}

// ParseTXT 把 mDNS TXT 记录数组解析为 key→value 映射。
// 裸属性(无 '=')以空字符串占位。
func ParseTXT(text []string) map[string]string {
	m := make(map[string]string, len(text))
	for _, kv := range text {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		} else {
			m[kv] = ""
		}
	}
	return m
}

// ApplyExtras 根据 service type 抽取深度字段,直接填入 *ServiceBanner。
// 已知 service type 见 spec.md "深度 Banner 识别" 表格;其它 service type
// 仅保留基础字段,深度字段保持零值。
func ApplyExtras(b *ServiceBanner, e ServiceEntry) {
	txt := ParseTXT(e.Text)
	switch e.ServiceName {
	case "_http._tcp.local":
		b.Path = txt["path"]
	case "_qdiscover._tcp.local":
		b.AccessType = txt["accessType"]
		b.AccessPort = txt["accessPort"]
		b.Model = txt["model"]
		b.DisplayModel = txt["displayModel"]
		b.FwVer = txt["fwVer"]
		b.FwBuildNum = txt["fwBuildNum"]
	case "_device-info._tcp.local":
		b.Model = txt["model"]
	}
}

// ParseEntry 把 ServiceEntry 转为 ServiceBanner。
//
// 流程:基础字段拷贝 → IPv4/IPv6 字符串化 → ApplyExtras 抽深度字段。
// 空输入(零值 ServiceEntry)不会 panic。
func ParseEntry(e ServiceEntry) ServiceBanner {
	b := ServiceBanner{
		Service:  e.ServiceName,
		Port:     e.Port,
		Name:     e.Name,
		Hostname: e.HostName,
		TTL:      e.TTL,
	}
	if v4 := e.AddrIPv4.To4(); v4 != nil {
		b.IPv4 = v4.String()
	}
	if v6 := e.AddrIPv6.To16(); v6 != nil {
		b.IPv6 = v6.String()
	}
	ApplyExtras(&b, e)
	return b
}
