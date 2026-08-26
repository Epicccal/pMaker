// cmd/pmaker-mcp 的 tool 测试,对应 tools.go。
//
// 覆盖范围:
//   - 用 mcp-go 的 mcptest 进程内 server 直接调 generate_yaml / generate_pcap
//     两个 tool,断言结构化输出(JSON);generate_pcap 额外用 gopacket 回读生成的 pcap,
//     确认 server 端链路与 CLI 等价。两工具共用同一套校验逻辑,generate_yaml 测试覆盖校验路径,
//     generate_pcap 测试覆盖出包路径。
//   - 路径穿越校验、参数校验(空 yaml)、扩展名校验。
//   - bindToolInput 的 BindArguments 失败分支、marshalResult 的 isError 路径。
//   - handler 写盘执行层故障路径。
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/mcptest"
)

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
