// cmd/pmaker-mcp 的 resources 测试,对应 resources.go。
//
// 覆盖范围:
//   - schema 资源(overview / 单层 / 未知层缺参数 / 非法层名 / overview 成功路径)。
//   - examples 资源(清单 / 单文件 / 空目录 / 无示例 / 缺文件 / 非 .yaml 后缀 / 路径穿越)。
//   - 纯函数:templateArg / isSafeName / listEmbeddedLayers / exampleDescription。
package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/mcptest"
)

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
