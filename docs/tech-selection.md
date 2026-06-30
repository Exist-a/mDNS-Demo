# 技术选型 (Tech Selection)

> 与 .trae/specs/mdns-asset-scanner/spec.md "技术选型" 表保持一致,
> 此处展开每个决策的依据与备选对比。

## 1. 语言与运行时
- **Go 1.24** (满足题目 "1.24 或之前" 硬约束)
- 单二进制静态链接,Linux amd64 直接 `./mdnsscan` 运行

## 2. mDNS 协议库
| 选项 | 评估 | 结论 |
|------|------|------|
| **github.com/miekg/dns** | DNS 报文 pack/unpack 最常用的 Go 库,与 RFC 6762/6763 完全兼容;支持 QU bit 单播响应 | **选用** |
| github.com/grandcat/zeroconf | 面向"监听 multicast 上 browse 全部 service",不适合逐 IP 主动探测 | 否 |
| github.com/hashicorp/mdns | 只发不收,需自写响应接收,稳定性风险大 | 否 |
| 自实现 RFC 6762 UDP 报文 | 灵活但 30 分钟内难做到稳定 | 否 |

> 选型说明:`grandcat/zeroconf` 原为 spec 推荐,但其 Browse API 走 multicast 224.0.0.251,
> 与"逐 IP 主动单播"场景不贴合。`miekg/dns` 是 grandcat 内部依赖的底层库,
> 直接使用更轻、可控性更高,且天然支持 RFC 6762 §5.4 的 QU bit 单播响应。

## 3. 探测模式
- **主动单播**(per-IP per-Port):与 "输入 IP 段" 直接对应,可跨 L3 边界
- 被动多播嗅探仅在本地链路有效,题目场景下漏报严重 — 放弃
- 双模混合收益不抵复杂度 — 放弃

## 4. CLI 框架
- **标准库 `flag`**:`scan` 单子命令,30 分钟挑战避免引入 cobra
- cobra:对单命令 CLI 收益小,编译慢、心智重 — 否

## 5. 输出格式
- **YAML 主输出 + `--json` 旁路**:题目示例即 YAML 文本,
  JSON 便于 `jq` / 二次消费
- 纯 JSON:人读体验差 — 否
- 严格按题目示例文本:不便二次处理 — 否

## 6. 并发模型
- **worker pool + semaphore**:防止 `10.0.0.0/24` 撑爆 goroutine
- 每个 worker 串行处理 (IP × Port) 子集,channel 缓冲大小可控
- `go test -race` 必须通过

## 7. 测试
- 标准库 `testing` + 表驱动
- 测试数据放 `testdata/fixtures/`,FOFA 公开响应脱敏后写入
- 端到端测试用本地回环 fake mDNS 服务器

## 8. 构建
- `Makefile` 目标 `build-linux` 一行交叉编译
- `go build -trimpath -ldflags="-s -w"` 产出独立二进制

## 9. 模块 / 包结构
```
mdnsscan/
├── cmd/mdnsscan/        # CLI 入口
├── internal/
│   ├── rangex/          # CIDR + 端口解析
│   ├── mdns/            # 主动探测 + worker pool
│   ├── banner/          # 深度 banner 解析
│   └── output/          # YAML / JSON 渲染
├── testdata/fixtures/   # FOFA 来源脱敏响应
└── docs/                # 需求 + 选型(本目录)
```

## 10. 不选取项说明
- **FOFA 在线 API 接入**:需要 token,30 分钟窗口内不增加认证交互
  → 改用离线 fixtures,既保证真实性又保证 CI 可重跑
- **持久化 / DB**:需求文档已列为非目标,本期不做
- **跨平台 GUI**:题目限定 CLI,本期不做

## 11. 风险与对策
| 风险 | 概率 | 对策 |
|------|------|------|
| grandcat/zeroconf API 字段命名偏差 | 中 | skeleton 已隔离到 `banner.ServiceEntry` 中性类型,实施期做适配 |
| Linux 跨编译环境差异 | 低 | `GOOS=linux GOARCH=amd64` + `-trimpath` |
| 真机 mDNS 设备响应过快/过慢 | 中 | 默认 `-timeout 2s`,允许命令行覆盖 |
