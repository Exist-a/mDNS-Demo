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

## 9. 实现现状(截至本 commit `bdd6f72`)

### 已完成

| 维度 | 状态 | 证据 |
|---|---|---|
| Go 1.24 编译 | ✅ | `go.mod` `go 1.24.0`,Linux amd64 二进制 4.1 MB |
| 主动 mDNS 单播探测 | ✅ | `internal/mdns/probe.go`,QU bit,worker pool,context 硬超时 |
| 深度 Banner 识别(qdiscover 6 字段) | ✅ | `internal/banner/parser.go` + 6 个 fixtures,11 字段全命中 |
| 输入解析(CIDR / 端口多形态) | ✅ | `internal/rangex/rangex.go`,8 个 case |
| YAML 输出 + JSON 输出 | ✅ | `internal/output/{yaml,json}.go`,6 个 case |
| CLI 集成 + 退出码 | ✅ | `cmd/mdnsscan/main.go`,5 个 case 覆盖 no-args / help / no-server / missing-arg |
| 端到端 fake mDNS 测试 | ✅ | `test/e2e_test.go` + `e2e_yaml_parse_test.go`,真实 miekg/dns 收发 |
| 外部 Python `yaml.safe_load` 验证 | ✅ | `scripts/validate_yaml.py` PASS,校验 11 字段 + TTL 类型 + accessType 值 |
| 外部 Python `json.load` 验证 | ✅ | `scripts/validate_json.py` PASS |
| Linux 跨编译 | ✅ | `make build-linux` → `bin/mdnsscan-linux-amd64` |
| 本地 git commit | ✅ | `bdd6f72` on `main`,27 文件 / 2308 行 |

### 未完成 / 已识别局限

1. **公开 GitHub 仓库推送** — 等待用户授权 + 提供 token
   - 本地 commit 已就绪,工作树干净
   - 推送时只需 `git remote add origin <URL>` + `git push -u origin main`

2. **`go test -race ./...` 在 Windows + MinGW 环境无法运行**
   - 现象:`exit code 0xc0000139 (STATUS_INVALID_IMAGE_FORMAT)`
   - 原因:MinGW 提供的 gcc 工具链生成的 race detector runtime DLL 与 Windows 不兼容
   - 影响范围:仅 race detector;非 race 模式 `go test ./...` 全部通过(33/33)
   - 在 Linux 目标机上 `-race` 应可正常工作(本机无 Linux 验证手段)
   - 缓解:CI/生产用 Linux runner;本地无需 race 验证

3. **真实网段烟测**
   - 当前所有路径测试均跑回环 fake DNS(127.0.0.1)验证协议正确性
   - 未在真实家庭/企业网段的 mDNS 设备上跑过端到端
   - 缓解:已把 FOFA 公开响应落 fixture,网络行为通过 fixture 回归

4. **IPv6 CIDR**
   - `rangex.ExpandCIDRs` 显式拒绝 IPv6
   - spec.md 已声明本期不覆盖(避免 30 分钟窗口内膨胀)

5. **FOFA 在线 API**
   - 没用真 FOFA API 拉数据(需 token,30 分钟挑战不开口子)
   - 用离线 fixture 覆盖所有 spec 中点名的 service type

### 自动化验收

```bash
# 跑全部测试
go test -count=1 ./...

# 渲染 yaml + json 样本
go test -count=1 -v -run TestE2E_EmitExamples ./test/...

# 外部 Python 解析验证
python scripts/validate_yaml.py out/example.yaml
python scripts/validate_json.py out/example.json

# 跨平台构建
make build          # 当前 OS
make build-linux    # linux/amd64
```
