package main

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestCLI_NoArgs_UsageAndExit2 验证无参数时输出 usage 且退出码 = 2。
func TestCLI_NoArgs_UsageAndExit2(t *testing.T) {
	exe := buildCLIForTest(t)
	cmd := exec.Command(exe)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatalf("expected non-zero exit")
	}
	if exitCode(err) != 2 {
		t.Errorf("exit code = %d, want 2", exitCode(err))
	}
	if !strings.Contains(stderr.String(), "mdnsscan") {
		t.Errorf("usage missing in stderr: %s", stderr.String())
	}
}

// TestCLI_HelpFlag 验证 --help / help 输出 usage 且退出码 0。
func TestCLI_HelpFlag(t *testing.T) {
	exe := buildCLIForTest(t)
	for _, arg := range []string{"help", "--help"} {
		t.Run(arg, func(t *testing.T) {
			cmd := exec.Command(exe, arg)
			var stdout bytes.Buffer
			cmd.Stdout = &stdout
			if err := cmd.Run(); err != nil {
				t.Fatalf("run: %v", err)
			}
			if !strings.Contains(stdout.String(), "用法:") || !strings.Contains(stdout.String(), "scan") {
				t.Errorf("help missing 关键词 in stdout:\n%s", stdout.String())
			}
		})
	}
}

// TestCLI_NoServer_Exit0_StderrHint 探测无 mDNS 目标时,退出码 0 且 stderr 提示。
func TestCLI_NoServer_Exit0_StderrHint(t *testing.T) {
	exe := buildCLIForTest(t)
	// 找一个未用的高位端口当"目标"
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadPort := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()

	cmd := exec.Command(exe, "scan",
		"-cidr", "127.0.0.1/32",
		"-ports", strconv.Itoa(deadPort),
		"-timeout", "200ms",
		"-workers", "1",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	t0 := time.Now()
	err = cmd.Run()
	elapsed := time.Since(t0)
	if err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}
	if elapsed > 3000*time.Millisecond {
		t.Errorf("CLI hung too long: %s", elapsed)
	}
	if !strings.Contains(stderr.String(), "no mdns asset found") {
		t.Errorf("missing 'no mdns asset found' in stderr:\n%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "services:") {
		t.Errorf("stdout should still contain 'services:' top key:\n%s", stdout.String())
	}
}

// TestCLI_MissingArg_Exit2 缺 -cidr / -ports 时退出码 2。
func TestCLI_MissingArg_Exit2(t *testing.T) {
	exe := buildCLIForTest(t)
	cmd := exec.Command(exe, "scan")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatalf("expected non-zero exit")
	}
	if exitCode(err) != 2 {
		t.Errorf("exit code = %d, want 2", exitCode(err))
	}
}

// buildCLIForTest 编译当前目录到 tmp 路径,返回可执行文件路径。
func buildCLIForTest(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	exe := filepath.Join(tmp, "mdnsscan-test"+exeSuffix())
	build := exec.Command("go", "build", "-o", exe, ".")
	if err := build.Run(); err != nil {
		t.Fatalf("go build: %v", err)
	}
	return exe
}

func exeSuffix() string {
	if os.PathSeparator == '/' {
		return ""
	}
	return ".exe"
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}
