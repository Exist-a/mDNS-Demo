# testdata/fixtures

放测试用 mDNS 响应报文(脱敏后),按 service type 分文件:

| 文件 | 内容 | 来源 |
|------|------|------|
| (待补) workstation.yaml | `_workstation._tcp.local` 完整字段 | FOFA 公开查询 `protocol="mdns"` |
| (待补) qdiscover.yaml   | `_qdiscover._tcp.local` 六字段      | 同上 + `banner*="qdiscover"` |
| (待补) afpovertcp.yaml  | `_afpovertcp._tcp.local` (Apple Filing Protocol) | FOFA 公开 + `banner*="afpovertcp"` |

格式建议(实施期定):
```yaml
service: _qdiscover._tcp.local
name: slw-nas
hostname: slw-nas.local
ipv4: 192.168.x.x
ipv6: fe80::265e:beff:fe69:a313
port: 5000
ttl: 10
text:
  - "accessType=https"
  - "accessPort=86"
  - "model=TS-X64"
  - "displayModel=TS-464C"
  - "fwVer=5.2.9"
  - "fwBuildNum=20260214"
```
