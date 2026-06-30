package output

import (
	"encoding/json"
	"io"

	"mdnsscan/internal/banner"
)

// WriteJSON 输出与 YAML 等价的 JSON,顶层 {services, answers:{PTR}}。
// 字段名与 YAML 对齐(camelCase 深度字段保持一致)。
func WriteJSON(w io.Writer, r ScanResult) error {
	type answers struct {
		PTR []string `json:"PTR"`
	}
	type out struct {
		Services map[string][]map[string]any `json:"services"`
		Answers  answers                     `json:"answers"`
	}
	services := make(map[string][]map[string]any, len(r.Services))
	for k, bs := range r.Services {
		arr := make([]map[string]any, 0, len(bs))
		for _, b := range bs {
			arr = append(arr, bannerToMap(b))
		}
		services[k] = arr
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out{
		Services: services,
		Answers:  answers{PTR: dedupPTRs(r.PTRs)},
	})
}

// bannerToMap 把 banner 序列化为 JSON object。空值省略,与 YAML 渲染对齐。
func bannerToMap(b banner.ServiceBanner) map[string]any {
	m := map[string]any{}
	if b.Name != "" {
		m["Name"] = b.Name
	}
	if b.IPv4 != "" {
		m["IPv4"] = b.IPv4
	}
	if b.IPv6 != "" {
		m["IPv6"] = b.IPv6
	}
	if b.Hostname != "" {
		m["Hostname"] = b.Hostname
	}
	if b.TTL > 0 {
		m["TTL"] = b.TTL
	}
	if b.Path != "" {
		m["path"] = b.Path
	}
	if b.AccessType != "" {
		m["accessType"] = b.AccessType
	}
	if b.AccessPort != "" {
		m["accessPort"] = b.AccessPort
	}
	if b.Model != "" {
		m["model"] = b.Model
	}
	if b.DisplayModel != "" {
		m["displayModel"] = b.DisplayModel
	}
	if b.FwVer != "" {
		m["fwVer"] = b.FwVer
	}
	if b.FwBuildNum != "" {
		m["fwBuildNum"] = b.FwBuildNum
	}
	return m
}
