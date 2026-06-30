# 需求文档 (Requirements)

> 对应 .trae/specs/mdns-asset-scanner/spec.md 内 "Why / What Changes / Impact"。
> 本文件面向人类读者,提供项目级概览与验收口径。

## 1. 背景
在内网或可控网段场景下,安全/运维人员经常需要盘点启用 mDNS 协议
(UDP/5353) 的资产。人工逐台登录成本高,通用端口扫描器(nmap masscan)
对 mDNS 的响应格式与字段深度识别支持有限,且无法对 `_qdiscover._tcp`
等厂商自定义 TXT 记录做结构化抽取。

## 2. 目标
交付一个 Go 编写的 CLI 工具 `mdnsscan`,能够:
1. 接收 IP 段 (`-cidr`) 与 UDP 端口范围 (`-ports`)
2. 主动单播发送 mDNS Query,收集 PTR/SRV/TXT/A/AAAA 记录
3. 按 service type 抽取深度 banner 字段,至少覆盖题目示例中的
   workstation / http / smb / qdiscover(qnap) / device-info / afpovertcp
4. 以 YAML 为主、`--json` 为辅输出结构化结果,便于管道/二次消费
5. 可在 Linux amd64 上直接运行,Go 版本 ≤ 1.24

## 3. 输入
| 参数   | 说明                                | 示例                                   |
|--------|-------------------------------------|----------------------------------------|
| -cidr  | 逗号分隔 CIDR 列表,仅 IPv4         | `192.168.1.0/24,10.0.0.0/28`           |
| -ports | 端口列表/区间,支持混合格式          | `5353` 或 `1-1024,5353` 或 `8000-8100` |
| -timeout | 单目标探测超时                    | `2s`(默认)                            |
| -workers | 并发 worker 数                   | `50`(默认)                            |
| -json  | 改用 JSON 输出                      | flag-only                              |

非法输入返回退出码 `2`,stderr 给出可读错误。

## 4. 输出 (YAML 默认)
顶层结构:
```yaml
services:
  9/tcp workstation:
    Name: slw-nas
    IPv4: x.x.x.x
    IPv6: fe80::...
    Hostname: slw-nas.local
    TTL: 10
  5000/tcp qdiscover:
    Name: slw-nas
    IPv4: x.x.x.x
    IPv6: fe80::...
    Hostname: slw-nas.local
    TTL: 10
    accessType: https
    accessPort: "86"
    model: TS-X64
    displayModel: TS-464C
    fwVer: 5.2.9
    fwBuildNum: "20260214"
answers:
  PTR:
    - _workstation._tcp.local
    - _qdiscover._tcp.local
```

`--json` 输出等价结构,顶层 `services` / `answers`。

## 5. 真实数据验证
- `testdata/fixtures/` 提供 ≥ 3 条脱敏后的 mDNS 响应报文,
  源自 FOFA 公开查询 `protocol="mdns"` 的活跃设备响应
- `internal/banner` 单测引用 fixtures 验证字段抽取,
  与题目示例字段深度严格对齐
- 端到端集成测试用本地回环 fake mDNS server 跑通 CLI

## 6. 退出码
| 码  | 含义                              |
|-----|-----------------------------------|
| 0   | 成功(含 0 资产)                  |
| 1   | 网络/运行时错误                  |
| 2   | 参数解析错误                      |

## 7. 非目标
- 跨 IPv6 段的链路本地多播嗅探(被动模式)本期不做
- 调用 FOFA 在线 API(需要 token,30 分钟挑战内不开口子)
- 持久化存储、UI、报表聚合

## 8. 验收清单
完整 checklist 见 `.trae/specs/mdns-asset-scanner/checklist.md`,
实现期每完成一条勾掉一条。
