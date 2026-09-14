// cmd/pmaker-mcp 的测试,对应 main.go。
//
// 覆盖范围:
//   - run():抽出的 main 可测核心(flag 解析、workdir 解析、MkdirAll、serve 透传)。
//   - envOr:环境变量命中/缺省分支。
//
// 共享 fixture(newTestServer / callTool / parseText / validScenarioYAML)也放在本文件,
// 供 tools_test.go / resources_test.go 复用(同 package main)。
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/mcptest"
	"github.com/mark3labs/mcp-go/server"
)

// newTestServer 用 mcptest 搭一个挂载本文件 tool handler 的进程内 server,
// workdir 指向 t.TempDir(),其下自动建 yaml/ pcap/ 子目录(与 main 一致)。
// 返回已启动的 server 与对应 config 的 workdir。
func newTestServer(t *testing.T) (*mcptest.Server, string) {
	t.Helper()
	workdir := t.TempDir()
	yamlDir := filepath.Join(workdir, "yaml")
	pcapDir := filepath.Join(workdir, "pcap")
	for _, d := range []string{yamlDir, pcapDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	cfg := config{workdir: workdir, yamlDir: yamlDir, pcapDir: pcapDir}

	srv := mcptest.NewUnstartedServer(t)
	srv.AddTool(generateYAMLTool(), cfg.handleGenerateYAML)
	srv.AddTool(generatePcapTool(), cfg.handleGeneratePcap)
	cfg.registerResources(srv)
	if err := srv.Start(t.Context()); err != nil {
		t.Fatalf("启动 mcptest server: %v", err)
	}
	return srv, workdir
}

// callTool 调用指定 tool 并返回结果(失败 Fatal)。
func callTool(t *testing.T, srv *mcptest.Server, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	var req mcp.CallToolRequest
	req.Params.Name = name
	req.Params.Arguments = args
	res, err := srv.Client().CallTool(t.Context(), req)
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	return res
}

// parseText 把 CallToolResult 的 TextContent 反序列化到 v(失败 Fatal)。
func parseText[T any](t *testing.T, res *mcp.CallToolResult) T {
	t.Helper()
	var out T
	var buf bytes.Buffer
	for _, c := range res.Content {
		tc, ok := c.(mcp.TextContent)
		if !ok {
			t.Fatalf("期望 TextContent,得到 %T", c)
		}
		buf.WriteString(tc.Text)
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("反序列化结果: %v\n原始: %s", err, buf.String())
	}
	return out
}

// validScenarioYAML 是一个合法的最小 HTTP flow 场景,用于成功路径测试。
const validScenarioYAML = `link_type: ethernet
flows:
  - name: http-get
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000, mss: 1460 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - http_request: { method: GET, url: /index.html, version: HTTP/1.1, headers: { Host: example.com } }
      - from: dst
        stack:
          - http_response: { status: 200, reason: OK, auto_content_length: true, headers: { Content-Length: 0 }, body: "hi" }
`

// readPcap 用 pcapgo 回读所有包(回读辅助,与 internal/builder/helpers_test.go 同构,本包独立)。
func readPcap(t *testing.T, data []byte) []gopacket.Packet {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcapgo reader: %v", err)
	}
	var pkts []gopacket.Packet
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		pkts = append(pkts, gopacket.NewPacket(raw, r.LinkType(), gopacket.Default))
	}
	return pkts
}

// ---------- run(): 抽出 main 的可测核心 ----------

func TestRunDefaultsToCwdWhenWorkdirEmpty(t *testing.T) {
	wd := t.TempDir()
	// 切到临时目录,使 Getwd 解析到它;run 不带 -workdir 应落到该目录下建 yaml/ pcap/。
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(wd); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	served := false
	err = run(nil, func(string) string { return "" }, func(_ *server.MCPServer) error {
		served = true
		return nil
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !served {
		t.Fatal("serve 应被调用")
	}
	for _, sub := range []string{"yaml", "pcap"} {
		if _, err := os.Stat(filepath.Join(wd, sub)); err != nil {
			t.Errorf("缺省 workdir 应建 %s/ 子目录: %v", sub, err)
		}
	}
}

func TestRunUsesWorkdirFlag(t *testing.T) {
	wd := t.TempDir()
	err := run([]string{"-workdir", wd}, func(string) string { return "" },
		func(_ *server.MCPServer) error { return nil })
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, sub := range []string{"yaml", "pcap"} {
		if _, err := os.Stat(filepath.Join(wd, sub)); err != nil {
			t.Errorf("应建 %s/ 子目录: %v", sub, err)
		}
	}
}

func TestRunUsesPmakerWorkdirEnv(t *testing.T) {
	wd := t.TempDir()
	// envOr 命中 PMAKER_WORKDIR 环境变量分支(不传 -workdir)。
	err := run(nil,
		func(k string) string {
			if k == "PMAKER_WORKDIR" {
				return wd
			}
			return ""
		},
		func(_ *server.MCPServer) error { return nil })
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(wd, "yaml")); err != nil {
		t.Errorf("env workdir 应建 yaml/ 子目录: %v", err)
	}
}

func TestRunPropagatesServeError(t *testing.T) {
	wd := t.TempDir()
	sentinel := os.ErrInvalid
	err := run([]string{"-workdir", wd}, func(string) string { return "" },
		func(_ *server.MCPServer) error { return sentinel })
	if err != sentinel {
		t.Fatalf("应透传 serve 错误,得到 %v", err)
	}
}

func TestRunFailsOnMkdirAllError(t *testing.T) {
	// 让 MkdirAll 失败:把 workdir 指向一个已存在文件(在其下建子目录必然失败)。
	blocker := t.TempDir()
	blockFile := filepath.Join(blocker, "block")
	if err := os.WriteFile(blockFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// -workdir 指向该文件;filepath.Abs 成功,但 MkdirAll(yamlDir) 失败。
	err := run([]string{"-workdir", blockFile}, func(string) string { return "" },
		func(_ *server.MCPServer) error { return nil })
	if err == nil {
		t.Fatal("MkdirAll 失败应返回错误")
	}
	if !strings.Contains(err.Error(), "创建目录") {
		t.Errorf("错误应含 \"创建目录\",得到 %v", err)
	}
}

// ---------- envOr ----------

func TestEnvOr(t *testing.T) {
	getenv := func(k string) string {
		switch k {
		case "SET":
			return "from-env"
		case "EMPTY":
			return ""
		default:
			return ""
		}
	}
	if got := envOr("SET", "fallback", getenv); got != "from-env" {
		t.Errorf("env 命中应返回 env 值,得到 %q", got)
	}
	if got := envOr("UNSET", "fallback", getenv); got != "fallback" {
		t.Errorf("env 未设应返回 fallback,得到 %q", got)
	}
	if got := envOr("EMPTY", "fallback", getenv); got != "fallback" {
		t.Errorf("空 env 应返回 fallback,得到 %q", got)
	}
}
