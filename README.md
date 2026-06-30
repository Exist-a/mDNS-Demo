# mdnsscan

mDNS 主动资产测绘 CLI。给定 IP 段 + UDP 端口范围,主动单播查询
mDNS 设备,并对响应做深度 banner 识别(覆盖 workstation / http /
smb / qdiscover(qnap) / device-info / afpovertcp 等服务类型)。

- 语言:Go 1.24 及更早
- 平台:Linux(同时可在 macOS / Windows 编译运行)
- 协议库:[github.com/miekg/dns](https://github.com/miekg/dns)(RFC 6762/6763)

## 快速上手

```bash
make build                # 在当前平台编译
./bin/mdnsscan scan -cidr 192.168.1.0/24 -ports 5353
```

跨平台打 Linux 包:
```bash
make build-linux          # 产出 bin/mdnsscan-linux-amd64
./bin/mdnsscan-linux-amd64 scan -cidr 192.168.1.0/24 -ports 5353
```

## CLI 用法

```
mdnsscan scan -cidr <CIDR[,CIDR,...]> -ports <PORT|RANGE[,...]> [flags]

flags:
  -cidr        目标 CIDR 列表 (例: 192.168.1.0/24,10.0.0.0/28)
  -ports       UDP 端口 (例: 5353 | 1-1024 | 1-1024,5353)
  -timeout     单目标探测超时 (默认 2s)
  -workers     并发 worker 数   (默认 50)
  -json        改用 JSON 输出   (默认 YAML)
```

## 输出示例 (YAML)
```yaml
services:
  9/tcp workstation:
    Name: slw-nas
    IPv4: x.x.x.x
    IPv6: fe80::265e:beff:fe69:a313
    Hostname: slw-nas.local
    TTL: 10
  5000/tcp qdiscover:
    Name: slw-nas
    IPv4: x.x.x.x
    IPv6: fe80::265e:beff:fe69:a313
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

## 退出码
| 码 | 含义 |
|----|------|
| 0  | 成功(含 0 资产) |
| 1  | 网络/运行时错误 |
| 2  | 参数错误 |

## 仓库布局
```
cmd/mdnsscan/        # CLI 入口
internal/
  rangex/            # CIDR + 端口解析
  mdns/              # 主动探测 + worker pool
  banner/            # 深度 banner 解析
  output/            # YAML / JSON 渲染
testdata/fixtures/   # FOFA 来源脱敏响应
docs/                # 需求 + 选型
```

## 文档
- [docs/requirements.md](docs/requirements.md):需求文档
- [docs/tech-selection.md](docs/tech-selection.md):技术选型
- [.trae/specs/mdns-asset-scanner/spec.md](.trae/specs/mdns-asset-scanner/spec.md):开发用 spec

## 真实数据
测试 fixture 取自 FOFA 公开查询 `protocol="mdns"` 的活跃响应,
脱敏后落在 `testdata/fixtures/`,单元测试与端到端测试都引用它。

## License
MIT
