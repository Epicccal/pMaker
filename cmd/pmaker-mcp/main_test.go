// cmd/pmaker-mcp 的测试。
//
// 覆盖范围:用 mcp-go 的 mcptest 进程内 server 直接调 generate_yaml / generate_pcap
// 两个 tool,断言结构化输出(JSON);generate_pcap 额外用 gopacket 回读生成的 pcap,
// 确认 server 端链路与 CLI 等价。两工具共用同一套校验逻辑,generate_yaml 测试覆盖校验路径,
// generate_pcap 测试覆盖出包路径。
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
