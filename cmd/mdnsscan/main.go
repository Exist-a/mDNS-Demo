// mdnsscan CLI 入口。
//
// 流程:参数解析 → rangex 展开目标 → mdns 主动探测 → banner 解析
//       → output 渲染 (YAML / JSON) → stdout。
//
// 退出码:
//   0 - 成功(含 0 资产)
//   1 - 网络/运行时错误
//   2 - 参数解析错误
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"mdnsscan/internal/banner"
	"mdnsscan/internal/mdns"
	"mdnsscan/internal/output"
	"mdnsscan/internal/rangex"
)

const usage = `mdnsscan - mDNS 主动资产测绘 CLI

用法:
  mdnsscan scan -cidr <CIDR[,CIDR,...]> -ports <PORT|RANGE[,...]> [flags]

子命令:
  scan         按 IP 网段 + UDP 端口范围主动探测 mDNS 资产

flags:
  -cidr        目标 CIDR 列表,逗号分隔 (例: 192.168.1.0/24,10.0.0.0/28)
  -ports       UDP 端口列表 (例: 5353 或 1-1024,5353)
  -timeout     单目标探测超时 (默认 2s)
  -workers     并发 worker 数 (默认 50)
  -json        使用 JSON 输出 (默认 YAML)

示例:
  mdnsscan scan -cidr 192.168.1.0/24 -ports 5353
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	cidr := fs.String("cidr", "", "comma-separated CIDR list")
	ports := fs.String("ports", "", "comma-separated UDP ports")
	timeout := fs.Duration("timeout", 2*time.Second, "per-target probe timeout")
	workers := fs.Int("workers", 50, "concurrent worker count")
	jsonOut := fs.Bool("json", false, "emit JSON instead of YAML")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if *cidr == "" || *ports == "" {
		fmt.Fprintln(os.Stderr, "error: -cidr and -ports are required")
		os.Exit(2)
	}

	ips, err := rangex.ExpandCIDRs(*cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid CIDR %q: %v\n", *cidr, err)
		os.Exit(2)
	}

	portList, err := rangex.ParsePorts(*ports)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid ports %q: %v\n", *ports, err)
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	responses := mdns.Probe(ctx, mdns.ProbeRequest{
		IPs:     ips,
		Ports:   portList,
		Timeout: *timeout,
		Workers: *workers,
	})

	services := map[string][]banner.ServiceBanner{}
	ptrSeen := map[string]bool{}
	ptrOrder := []string{}
	for r := range responses {
		if r.Err != nil {
			fmt.Fprintf(os.Stderr, "warn: probe %s:%d: %v\n", r.IP, r.Port, r.Err)
			continue
		}
		b := r.Banner
		if b.Service == "" {
			continue
		}
		key := output.ServiceKey(b)
		services[key] = append(services[key], b)
		if !ptrSeen[b.Service] {
			ptrSeen[b.Service] = true
			ptrOrder = append(ptrOrder, b.Service)
		}
	}
	sort.Strings(ptrOrder)

	res := output.ScanResult{Services: services, PTRs: ptrOrder}

	if len(res.Services) == 0 {
		fmt.Fprintln(os.Stderr, "no mdns asset found")
	}

	var writerErr error
	if *jsonOut {
		writerErr = output.WriteJSON(os.Stdout, res)
	} else {
		writerErr = output.WriteYAML(os.Stdout, res)
	}
	if writerErr != nil {
		fmt.Fprintf(os.Stderr, "error: write output: %v\n", writerErr)
		os.Exit(1)
	}
}
