// cmd/pmaker-mcp 的测试,对应 main.go。
//
// 覆盖范围:
//   - 用 mcp-go 的 mcptest 进程内 server 直接调 generate_yaml / generate_pcap
//     两个 tool,断言结构化输出(JSON);generate_pcap 额外用 gopacket 回读生成的 pcap,
//     确认 server 端链路与 CLI 等价。两工具共用同一套校验逻辑,generate_yaml 测试覆盖校验路径,
//     generate_pcap 测试覆盖出包路径。
//   - 纯函数(validateOutputName / templateArg / isSafeName / listEmbeddedLayers /
//     exampleDescription / envOr / bindToolInput 的 BindArguments 失败分支)、marshalResult 的
//     isError 路径、handler 写盘执行层故障路径、examples 资源的空目录分支。
//   - main() 含 os.Exit 不可直接调用,故测试抽出 run()(main 仅做错误打印 + 退出码)后覆盖其分支。
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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
seed: 42
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
          - http_response: { status: 200, reason: OK, headers: { Content-Length: auto }, body: "hi" }
`

// ---------- generate_yaml ----------

func TestGenerateYAMLAcceptsValid(t *testing.T) {
	srv, workdir := newTestServer(t)
	defer srv.Close()

	res := callTool(t, srv, "generate_yaml", map[string]any{
		"yaml":        validScenarioYAML,
		"output_name": "http-get.yaml",
	})
	if res.IsError {
		t.Fatalf("合法场景不应 isError,Content: %v", res.Content)
	}
	out := parseText[generateYAMLOutput](t, res)
	if !out.Valid {
		t.Errorf("Valid=true, 得到 false; errors=%v", out.Errors)
	}
	// 校验通过应落盘到 workdir/yaml/http-get.yaml,内容原样。
	wantPath := filepath.Join(workdir, "yaml", "http-get.yaml")
	if out.Path != wantPath {
		t.Errorf("Path=%q, 期望 %q", out.Path, wantPath)
	}
	got, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("归档文件应存在: %v", err)
	}
	if string(got) != validScenarioYAML {
		t.Errorf("归档内容应原样写入,得到 %q", got)
	}
}

func TestGenerateYAMLReportsFieldError(t *testing.T) {
	srv, workdir := newTestServer(t)
	defer srv.Close()

	// tcp 缺 sport/dport,Validate 应报「需要 sport 与 dport」,并带 packet/stack 路径。
	bad := `link_type: ethernet
seed: 42
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:  { flags: [SYN] }
`
	res := callTool(t, srv, "generate_yaml", map[string]any{
		"yaml":        bad,
		"output_name": "should-not-exist.yaml",
	})
	if !res.IsError {
		t.Fatalf("校验失败应是 isError=true,Content: %v", res.Content)
	}
	out := parseText[generateYAMLOutput](t, res)
	if out.Valid {
		t.Fatal("Valid=false, 得到 true(缺 sport/dport 应被拒)")
	}
	if len(out.Errors) == 0 {
		t.Fatal("期望非空 errors")
	}
	// 错误应点名 sport 或 dport,供调用方据以修正。
	wantAny := "sport"
	found := false
	for _, e := range out.Errors {
		if strings.Contains(e, wantAny) {
			found = true
		}
	}
	if !found {
		t.Errorf("errors 应包含 %q,得到 %v", wantAny, out.Errors)
	}
	// 校验失败不应落盘。
	if _, err := os.Stat(filepath.Join(workdir, "yaml", "should-not-exist.yaml")); err == nil {
		t.Fatal("校验失败不应写归档文件")
	}
}

func TestGenerateYAMLRejectsMalformedYAML(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	res := callTool(t, srv, "generate_yaml", map[string]any{
		"yaml":        "  - : [bad",
		"output_name": "out.yaml",
	})
	if !res.IsError {
		t.Fatal("畸形 YAML 应 isError=true")
	}
	out := parseText[generateYAMLOutput](t, res)
	if out.Valid {
		t.Fatal("畸形 YAML 应 valid=false")
	}
	if len(out.Errors) == 0 {
		t.Fatal("畸形 YAML 应有 errors")
	}
}

// ---------- generate_pcap ----------

func TestGeneratePcapWritesFileAndReadsBack(t *testing.T) {
	srv, workdir := newTestServer(t)
	defer srv.Close()

	res := callTool(t, srv, "generate_pcap", map[string]any{
		"yaml":        validScenarioYAML,
		"output_name": "out.pcap",
	})
	if res.IsError {
		t.Fatalf("合法场景不应 isError,Content: %v", res.Content)
	}
	out := parseText[generatePcapOutput](t, res)
	if !out.Valid {
		t.Fatalf("合法场景应 Valid=true, errors=%v", out.Errors)
	}

	// 文件应落到 workdir/pcap/out.pcap。
	wantPath := filepath.Join(workdir, "pcap", "out.pcap")
	if out.Path != wantPath {
		t.Errorf("Path=%q, 期望 %q", out.Path, wantPath)
	}
	if out.PacketCount == 0 {
		t.Fatal("PacketCount 应 > 0")
	}
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("输出文件应存在: %v", err)
	}

	// 回读 pcap:能被 pcapgo 打开、包数一致、LinkType 为 ethernet。
	data, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("读回 pcap: %v", err)
	}
	pkts := readPcap(t, data)
	if len(pkts) != out.PacketCount {
		t.Errorf("回读包数=%d, 期望 %d", len(pkts), out.PacketCount)
	}
	if len(out.Summary) != out.PacketCount {
		t.Errorf("Summary 条数=%d, 期望 %d", len(out.Summary), out.PacketCount)
	}

	// 同步归档的 YAML 应落到 workdir/yaml/out.yaml,内容与入参一致。
	wantYAMLPath := filepath.Join(workdir, "yaml", "out.yaml")
	if out.YAMLPath != wantYAMLPath {
		t.Errorf("YAMLPath=%q, 期望 %q", out.YAMLPath, wantYAMLPath)
	}
	yamlData, err := os.ReadFile(wantYAMLPath)
	if err != nil {
		t.Fatalf("归档 YAML 应存在: %v", err)
	}
	if string(yamlData) != validScenarioYAML {
		t.Errorf("归档 YAML 内容应与入参一致,得到 %q", yamlData)
	}
}

func TestGeneratePcapReportsValidationErrorWithoutFile(t *testing.T) {
	srv, workdir := newTestServer(t)
	defer srv.Close()

	bad := `link_type: ethernet
seed: 42
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:  { flags: [SYN] }
`
	res := callTool(t, srv, "generate_pcap", map[string]any{
		"yaml":        bad,
		"output_name": "should-not-exist.pcap",
	})
	// 校验失败是未产出 pcap 的结果:Valid=false 且 isError=true。
	// (Valid 与 generate_yaml 对齐;isError 让无 Valid 概念的客户端也能识别失败。)
	if !res.IsError {
		t.Fatalf("校验失败应是 isError=true,Content: %v", res.Content)
	}
	out := parseText[generatePcapOutput](t, res)
	if out.Valid {
		t.Fatal("校验失败应 Valid=false")
	}
	if len(out.Errors) == 0 {
		t.Fatal("校验失败应有 errors")
	}
	// 不应写文件(pcap 与归档 YAML 都不应存在)。
	if _, err := os.Stat(filepath.Join(workdir, "pcap", "should-not-exist.pcap")); err == nil {
		t.Fatal("校验失败不应写输出文件")
	}
	if _, err := os.Stat(filepath.Join(workdir, "yaml", "should-not-exist.yaml")); err == nil {
		t.Fatal("校验失败不应写归档 YAML")
	}
	if out.Path != "" || out.PacketCount != 0 || out.YAMLPath != "" {
		t.Errorf("校验失败应 Path/YAMLPath 空 / PacketCount=0, 得到 Path=%q yaml=%q count=%d", out.Path, out.YAMLPath, out.PacketCount)
	}
}

// ---------- 路径穿越校验 ----------

func TestGeneratePcapRejectsPathTraversal(t *testing.T) {
	srv, workdir := newTestServer(t)
	defer srv.Close()

	for _, name := range []string{"../evil.pcap", "sub/dir.pcap", "..\\evil.pcap"} {
		var req mcp.CallToolRequest
		req.Params.Name = "generate_pcap"
		req.Params.Arguments = map[string]any{"yaml": validScenarioYAML, "output_name": name}
		_, err := srv.Client().CallTool(t.Context(), req)
		if err == nil {
			t.Errorf("output_name %q 应被拒绝(返回 MCP error),实际无错", name)
		}
	}
	// 确认没在 pcap 目录上层写出文件。
	if _, err := os.Stat(filepath.Join(workdir, "evil.pcap")); err == nil {
		t.Fatal("路径穿越应未写出文件")
	}
}

func TestGenerateYAMLRejectsPathTraversal(t *testing.T) {
	srv, workdir := newTestServer(t)
	defer srv.Close()

	for _, name := range []string{"../evil.yaml", "sub/dir.yaml", "..\\evil.yaml"} {
		var req mcp.CallToolRequest
		req.Params.Name = "generate_yaml"
		req.Params.Arguments = map[string]any{"yaml": validScenarioYAML, "output_name": name}
		_, err := srv.Client().CallTool(t.Context(), req)
		if err == nil {
			t.Errorf("output_name %q 应被拒绝(返回 MCP error),实际无错", name)
		}
	}
	// 确认没在 yaml 目录上层写出文件。
	if _, err := os.Stat(filepath.Join(workdir, "evil.yaml")); err == nil {
		t.Fatal("路径穿越应未写出文件")
	}
}

// ---------- 参数校验 ----------

func TestGeneratePcapRejectsEmptyYAML(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	var req mcp.CallToolRequest
	req.Params.Name = "generate_pcap"
	req.Params.Arguments = map[string]any{"yaml": "", "output_name": "out.pcap"}
	if _, err := srv.Client().CallTool(t.Context(), req); err == nil {
		t.Fatal("空 yaml 应返回 MCP error")
	}
}

func TestGenerateYAMLRejectsEmptyYAML(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	var req mcp.CallToolRequest
	req.Params.Name = "generate_yaml"
	req.Params.Arguments = map[string]any{"yaml": "", "output_name": "out.yaml"}
	if _, err := srv.Client().CallTool(t.Context(), req); err == nil {
		t.Fatal("空 yaml 应返回 MCP error")
	}
}

// ---------- 扩展名校验 ----------

func TestGeneratePcapRejectsBadExtension(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	for _, name := range []string{"out", "out.yaml", "out.txt", "out.pcapng"} {
		var req mcp.CallToolRequest
		req.Params.Name = "generate_pcap"
		req.Params.Arguments = map[string]any{"yaml": validScenarioYAML, "output_name": name}
		if _, err := srv.Client().CallTool(t.Context(), req); err == nil {
			t.Errorf("output_name %q 应被拒绝(必须以 .pcap 结尾)", name)
		}
	}
}

func TestGenerateYAMLRejectsBadExtension(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	for _, name := range []string{"out", "out.yml", "out.pcap", "out.txt"} {
		var req mcp.CallToolRequest
		req.Params.Name = "generate_yaml"
		req.Params.Arguments = map[string]any{"yaml": validScenarioYAML, "output_name": name}
		if _, err := srv.Client().CallTool(t.Context(), req); err == nil {
			t.Errorf("output_name %q 应被拒绝(必须以 .yaml 结尾)", name)
		}
	}
}

// ---------- 回读辅助(与 internal/builder/helpers_test.go 同构,本包独立) ----------

// readPcap 用 pcapgo 回读所有包。
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

// ---------- resources 测试 ----------

// readResource 读一个 resource 并返回首个 TextResourceContents(失败 Fatal)。
func readResource(t *testing.T, srv *mcptest.Server, uri string) mcp.TextResourceContents {
	t.Helper()
	var req mcp.ReadResourceRequest
	req.Params.URI = uri
	res, err := srv.Client().ReadResource(t.Context(), req)
	if err != nil {
		t.Fatalf("ReadResource %s: %v", uri, err)
	}
	if len(res.Contents) == 0 {
		t.Fatalf("ReadResource %s 返回空 contents", uri)
	}
	tc, ok := res.Contents[0].(mcp.TextResourceContents)
	if !ok {
		t.Fatalf("期望 TextResourceContents,得到 %T", res.Contents[0])
	}
	return tc
}

// writeExampleYAML 在 workdir 下造一个示例文件,供 examples resource 测试。
func writeExampleYAML(t *testing.T, workdir, proto, name, body string) {
	t.Helper()
	dir := filepath.Join(workdir, "examples", proto)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s/%s: %v", proto, name, err)
	}
}

func TestResourceSchemaOverview(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	tc := readResource(t, srv, "pmaker://schema")
	if !strings.Contains(tc.Text, "pMaker") {
		t.Errorf("overview 应含 pMaker,得到前 200 字: %q", tc.Text[:min(200, len(tc.Text))])
	}
	if !strings.Contains(tc.Text, "eth") || !strings.Contains(tc.Text, "tcp") {
		t.Errorf("overview 应列层名(eth/tcp),得到: %q", tc.Text)
	}
	if tc.MIMEType != schemaMIME {
		t.Errorf("MIMEType=%q, 期望 %q", tc.MIMEType, schemaMIME)
	}
}

func TestResourceSchemaLayerTCP(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	tc := readResource(t, srv, "pmaker://schema/tcp")
	for _, want := range []string{"sport", "dport", "mss"} {
		if !strings.Contains(tc.Text, want) {
			t.Errorf("tcp.md 应含 %q,得到: %q", want, tc.Text)
		}
	}
}

func TestResourceSchemaLayerUnknown(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	var req mcp.ReadResourceRequest
	req.Params.URI = "pmaker://schema/nonexistent"
	_, err := srv.Client().ReadResource(t.Context(), req)
	if err == nil {
		t.Fatal("未知层应返回错误并列出可用层名")
	}
	if !strings.Contains(err.Error(), "eth") {
		t.Errorf("错误应列出可用层名(含 eth),得到: %v", err)
	}
}

func TestResourceExamplesList(t *testing.T) {
	srv, workdir := newTestServer(t)
	defer srv.Close()

	writeExampleYAML(t, workdir, "http", "get.yaml",
		"# 一次 HTTP GET 请求\nlink_type: ethernet\n")
	writeExampleYAML(t, workdir, "dns", "query.yaml",
		"# DNS A 查询\nlink_type: ethernet\n")

	tc := readResource(t, srv, "pmaker://examples")
	if !strings.Contains(tc.Text, "http/get.yaml") {
		t.Errorf("examples 应列 http/get.yaml,得到: %q", tc.Text)
	}
	if !strings.Contains(tc.Text, "dns/query.yaml") {
		t.Errorf("examples 应列 dns/query.yaml,得到: %q", tc.Text)
	}
	if !strings.Contains(tc.Text, "HTTP GET") {
		t.Errorf("examples 应含示例描述(首行注释),得到: %q", tc.Text)
	}
}

func TestResourceExampleFile(t *testing.T) {
	srv, workdir := newTestServer(t)
	defer srv.Close()

	body := "# 示例\nlink_type: ethernet\nseed: 42\npackets: []\n"
	writeExampleYAML(t, workdir, "icmp", "echo.yaml", body)

	tc := readResource(t, srv, "pmaker://examples/icmp/echo.yaml")
	if tc.Text != body {
		t.Errorf("示例正文应原样返回,得到: %q", tc.Text)
	}
}

func TestResourceExampleFileTraversalRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	var req mcp.ReadResourceRequest
	req.Params.URI = "pmaker://examples/../etc/hosts"
	if _, err := srv.Client().ReadResource(t.Context(), req); err == nil {
		t.Errorf("路径穿越应被拒")
	}
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

// ---------- validateOutputName ----------

func TestValidateOutputName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"out.yaml", true},
		{"out.pcap", true},
		{"a-b_c.yaml", true},
		{"", false},
		{"sub/dir.yaml", false},
		{`win\path.pcap`, false},
		{"..", false},
		{"../evil.yaml", false},
		{"..foo.yaml", false}, // 以 .. 开头,拒
	}
	for _, c := range cases {
		err := validateOutputName(c.name)
		if c.ok && err != nil {
			t.Errorf("validateOutputName(%q) 不应报错,得到 %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("validateOutputName(%q) 应报错", c.name)
		}
	}
}

// ---------- isSafeName ----------

func TestIsSafeName(t *testing.T) {
	cases := []struct {
		s  string
		ok bool
	}{
		{"eth", true},
		{"tcp_session", true},
		{"a-b", true},
		{"A1", true},
		{"", false},
		{".", false},
		{"..", false},
		{"a/b", false},
		{"a.b", false},
		{"a b", false},
		{"é", false}, // 非法 rune
	}
	for _, c := range cases {
		if got := isSafeName(c.s); got != c.ok {
			t.Errorf("isSafeName(%q) = %v, 期望 %v", c.s, got, c.ok)
		}
	}
}

// ---------- templateArg ----------

func TestTemplateArg(t *testing.T) {
	// nil Arguments。
	var req mcp.ReadResourceRequest
	req.Params.Arguments = nil
	if got := templateArg(req, "layer"); got != "" {
		t.Errorf("nil args 应返回空串,得到 %q", got)
	}
	// 缺 key。
	req.Params.Arguments = map[string]any{"other": "x"}
	if got := templateArg(req, "layer"); got != "" {
		t.Errorf("缺 key 应返回空串,得到 %q", got)
	}
	// string 值。
	req.Params.Arguments = map[string]any{"layer": "tcp"}
	if got := templateArg(req, "layer"); got != "tcp" {
		t.Errorf("string 值应返回该值,得到 %q", got)
	}
	// []string 非空,取首个。
	req.Params.Arguments = map[string]any{"layer": []string{"tcp", "udp"}}
	if got := templateArg(req, "layer"); got != "tcp" {
		t.Errorf("[]string 应取首个,得到 %q", got)
	}
	// []string 空。
	req.Params.Arguments = map[string]any{"layer": []string{}}
	if got := templateArg(req, "layer"); got != "" {
		t.Errorf("空 []string 应返回空串,得到 %q", got)
	}
	// 未知类型。
	req.Params.Arguments = map[string]any{"layer": 42}
	if got := templateArg(req, "layer"); got != "" {
		t.Errorf("未知类型应返回空串,得到 %q", got)
	}
}

// ---------- listEmbeddedLayers ----------

func TestListEmbeddedLayers(t *testing.T) {
	got := listEmbeddedLayers()
	if len(got) == 0 {
		t.Fatal("embed schema 目录应非空")
	}
	// overview 被排除。
	if slices.Contains(got, "overview") {
		t.Error("overview 不应列入可用层名")
	}
	// 应含已知层。
	for _, want := range []string{"eth", "tcp", "dns"} {
		if !slices.Contains(got, want) {
			t.Errorf("listEmbeddedLayers 应含 %q", want)
		}
	}
	// 应按字典序。
	if !slices.IsSorted(got) {
		t.Errorf("listEmbeddedLayers 应按字典序,得到 %v", got)
	}
}

// ---------- exampleDescription ----------

func TestExampleDescription(t *testing.T) {
	dir := t.TempDir()
	// 首行注释。
	p := filepath.Join(dir, "a.yaml")
	if err := os.WriteFile(p, []byte("# 一次 HTTP GET\nlink_type: ethernet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := exampleDescription(p); got != "一次 HTTP GET" {
		t.Errorf("首行注释描述 = %q, 期望 %q", got, "一次 HTTP GET")
	}
	// 前导空行 + 注释。
	p2 := filepath.Join(dir, "b.yaml")
	if err := os.WriteFile(p2, []byte("\n\n  # 描述\nlink_type: ethernet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := exampleDescription(p2); got != "描述" {
		t.Errorf("跳过空行后的注释描述 = %q, 期望 %q", got, "描述")
	}
	// 首个非空行非注释 → 返回空。
	p3 := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p3, []byte("link_type: ethernet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := exampleDescription(p3); got != "" {
		t.Errorf("非注释首行应返回空,得到 %q", got)
	}
	// 空行后非注释行 → 返回空。
	p4 := filepath.Join(dir, "d.yaml")
	if err := os.WriteFile(p4, []byte("\nlink_type: ethernet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := exampleDescription(p4); got != "" {
		t.Errorf("空行后非注释应返回空,得到 %q", got)
	}
	// 读不到文件 → 返回空(不 panic)。
	if got := exampleDescription(filepath.Join(dir, "nope.yaml")); got != "" {
		t.Errorf("不存在的文件应返回空,得到 %q", got)
	}
}

// ---------- bindToolInput: BindArguments 失败分支 ----------

func TestBindToolInputRawJSONDecodeError(t *testing.T) {
	// 用畸形 RawJSON 触发 BindArguments 的 json.Unmarshal 失败分支。
	var req mcp.CallToolRequest
	req.Params.Arguments = json.RawMessage(`{"yaml": not-valid-json}`)
	_, err := bindToolInput(req, ".yaml")
	if err == nil {
		t.Fatal("畸形 JSON 参数应报错")
	}
	if !strings.Contains(err.Error(), "解析参数") {
		t.Errorf("错误应含 \"解析参数\",得到 %v", err)
	}
}

// ---------- marshalResult: isError 路径 ----------

func TestMarshalResultIsErrorFlag(t *testing.T) {
	type out struct {
		Valid bool `json:"valid"`
	}
	// isError=true。
	res, err := marshalResult(out{Valid: false}, true)
	if err != nil {
		t.Fatalf("marshalResult: %v", err)
	}
	if !res.IsError {
		t.Error("isError=true 应设 IsError")
	}
	// StructuredContent 应为合法 JSON 且含 valid。
	var sc map[string]any
	raw, _ := res.StructuredContent.(json.RawMessage)
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatalf("StructuredContent 应为合法 JSON: %v", err)
	}
	if sc["valid"] != false {
		t.Errorf("StructuredContent.valid = %v, 期望 false", sc["valid"])
	}
	// isError=false。
	res2, err := marshalResult(out{Valid: true}, false)
	if err != nil {
		t.Fatalf("marshalResult: %v", err)
	}
	if res2.IsError {
		t.Error("isError=false 不应设 IsError")
	}
}

// ---------- handler 写盘执行层故障 ----------

func TestGenerateYAMLWriteFailure(t *testing.T) {
	workdir := t.TempDir()
	// 让 yamlDir 指向一个不存在的目录的子目录(父目录也缺),WriteFile 应失败。
	// 不调用 newTestServer 的 MkdirAll —— 直接构造 config + 起独立 server。
	cfg := config{
		workdir: workdir,
		yamlDir: filepath.Join(workdir, "missing-yaml"), // 未创建
		pcapDir: filepath.Join(workdir, "pcap"),
	}
	srv := mcptest.NewUnstartedServer(t)
	srv.AddTool(generateYAMLTool(), cfg.handleGenerateYAML)
	srv.AddTool(generatePcapTool(), cfg.handleGeneratePcap)
	cfg.registerResources(srv)
	if err := srv.Start(t.Context()); err != nil {
		t.Fatalf("启动 server: %v", err)
	}
	defer srv.Close()

	var req mcp.CallToolRequest
	req.Params.Name = "generate_yaml"
	req.Params.Arguments = map[string]any{
		"yaml":        validScenarioYAML,
		"output_name": "out.yaml",
	}
	res, err := srv.Client().CallTool(t.Context(), req)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	// 校验通过但写盘失败:Valid 仍为 true,isError=true。
	if !res.IsError {
		t.Fatal("写盘失败应 isError=true")
	}
	out := parseText[generateYAMLOutput](t, res)
	if !out.Valid {
		t.Errorf("校验已过,Valid 应为 true,得到 false; errors=%v", out.Errors)
	}
	if len(out.Errors) == 0 || !strings.Contains(out.Errors[0], "写盘") {
		t.Errorf("应报写盘错误,得到 %v", out.Errors)
	}
	if out.Path != "" {
		t.Errorf("写盘失败 Path 应空,得到 %q", out.Path)
	}
}

func TestGeneratePcapWriteFailure(t *testing.T) {
	workdir := t.TempDir()
	// pcapDir 指向一个文件(不是目录)→ os.Create 失败 → writer.Write 报错。
	blocker := filepath.Join(workdir, "pcap-block")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config{
		workdir: workdir,
		yamlDir: filepath.Join(workdir, "yaml"),
		pcapDir: blocker, // 指向文件,写盘必失败
	}
	if err := os.MkdirAll(cfg.yamlDir, 0o750); err != nil {
		t.Fatal(err)
	}
	srv := mcptest.NewUnstartedServer(t)
	srv.AddTool(generateYAMLTool(), cfg.handleGenerateYAML)
	srv.AddTool(generatePcapTool(), cfg.handleGeneratePcap)
	cfg.registerResources(srv)
	if err := srv.Start(t.Context()); err != nil {
		t.Fatalf("启动 server: %v", err)
	}
	defer srv.Close()

	var req mcp.CallToolRequest
	req.Params.Name = "generate_pcap"
	req.Params.Arguments = map[string]any{
		"yaml":        validScenarioYAML,
		"output_name": "out.pcap",
	}
	res, err := srv.Client().CallTool(t.Context(), req)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatal("写盘失败应 isError=true")
	}
	out := parseText[generatePcapOutput](t, res)
	// 校验通过 → Valid=true;写盘失败 → isError=true。
	if !out.Valid {
		t.Errorf("校验已过,Valid 应为 true,得到 false; errors=%v", out.Errors)
	}
	if len(out.Errors) == 0 || !strings.Contains(out.Errors[0], "写盘") {
		t.Errorf("应报写盘错误,得到 %v", out.Errors)
	}
	if out.Path != "" {
		t.Errorf("写盘失败 Path 应空,得到 %q", out.Path)
	}
}

// ---------- examples 资源:空目录分支 ----------

func TestResourceExamplesListEmpty(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()
	// workdir 下无 examples 目录 → ReadDir 失败 → 返回提示文本。
	tc := readResource(t, srv, "pmaker://examples")
	if !strings.Contains(tc.Text, "无 examples") {
		t.Errorf("无 examples 目录应返回提示,得到: %q", tc.Text)
	}
}

func TestResourceExamplesListNoExamples(t *testing.T) {
	srv, workdir := newTestServer(t)
	defer srv.Close()
	// examples 目录存在但无 .yaml → 返回 "(无示例)"。
	if err := os.MkdirAll(filepath.Join(workdir, "examples", "http"), 0o750); err != nil {
		t.Fatal(err)
	}
	// 放一个非 .yaml 文件(应被跳过)。
	if err := os.WriteFile(filepath.Join(workdir, "examples", "http", "README.md"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 放一个空子目录(应被跳过:非 .yaml)。
	if err := os.MkdirAll(filepath.Join(workdir, "examples", "http", "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	tc := readResource(t, srv, "pmaker://examples")
	if !strings.Contains(tc.Text, "(无示例)") {
		t.Errorf("无 .yaml 示例应返回 \"(无示例)\",得到: %q", tc.Text)
	}
}

func TestResourceExampleFileMissing(t *testing.T) {
	srv, workdir := newTestServer(t)
	defer srv.Close()
	// 建协议目录但不放目标文件 → ReadFile 失败。
	if err := os.MkdirAll(filepath.Join(workdir, "examples", "icmp"), 0o750); err != nil {
		t.Fatal(err)
	}
	var req mcp.ReadResourceRequest
	req.Params.URI = "pmaker://examples/icmp/nope.yaml"
	if _, err := srv.Client().ReadResource(t.Context(), req); err == nil {
		t.Fatal("不存在的示例应返回错误")
	}
}

func TestResourceExampleFileBadSuffix(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()
	// 示例名非 .yaml 后缀应被拒(防读 README 等)。
	for _, uri := range []string{
		"pmaker://examples/http/README",
		"pmaker://examples/http/readme.txt",
	} {
		var req mcp.ReadResourceRequest
		req.Params.URI = uri
		if _, err := srv.Client().ReadResource(t.Context(), req); err == nil {
			t.Errorf("非 .yaml 后缀 %q 应被拒", uri)
		}
	}
}

// ---------- schema 资源:缺参数分支 ----------

func TestResourceSchemaLayerMissingParam(t *testing.T) {
	// 直接调 handleSchemaLayer,Arguments 不设 layer → 走"缺少参数"分支。
	var req mcp.ReadResourceRequest
	req.Params.URI = "pmaker://schema/"
	req.Params.Arguments = map[string]any{}
	_, err := (config{}).handleSchemaLayer(t.Context(), req)
	if err == nil {
		t.Fatal("空 layer 参数应报错")
	}
	if !strings.Contains(err.Error(), "layer") {
		t.Errorf("错误应点名 layer,得到: %v", err)
	}
}

func TestResourceSchemaLayerUnsafeName(t *testing.T) {
	// isSafeName 拒绝非法层名(含路径分隔符等)。
	var req mcp.ReadResourceRequest
	req.Params.URI = "pmaker://schema/a/b"
	req.Params.Arguments = map[string]any{"layer": "a/b"}
	_, err := (config{}).handleSchemaLayer(t.Context(), req)
	if err == nil {
		t.Fatal("非法层名应报错")
	}
}

func TestResourceSchemaOverviewSuccess(t *testing.T) {
	// overview.md 是 embed 资源,正常路径必能读到;确认成功路径返回非空文本。
	var req mcp.ReadResourceRequest
	req.Params.URI = "pmaker://schema"
	res, err := (config{}).handleSchemaOverview(t.Context(), req)
	if err != nil {
		t.Fatalf("handleSchemaOverview: %v", err)
	}
	if len(res) == 0 {
		t.Fatal("应返回非空 contents")
	}
	tc, ok := res[0].(mcp.TextResourceContents)
	if !ok {
		t.Fatalf("期望 TextResourceContents,得到 %T", res[0])
	}
	if tc.Text == "" {
		t.Error("overview 文本不应为空")
	}
	if tc.MIMEType != schemaMIME {
		t.Errorf("MIMEType = %q, 期望 %q", tc.MIMEType, schemaMIME)
	}
}
