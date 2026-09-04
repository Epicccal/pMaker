// cmd/pmaker-mcp 的 resources 测试,对应 resources.go。
//
// 覆盖范围:
//   - schema 资源(overview / 单层 / 未知层缺参数 / 非法层名 / overview 成功路径)。
//   - examples 资源(清单 / 单文件 / 空目录 / 无示例 / 缺文件 / 非 .yaml 后缀 / 路径穿越)。
//   - 纯函数:templateArg / isSafeName / listEmbeddedLayers / exampleDescription。
package main

import (
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

// _conventions 是单独 AddResource 注册的固定 resource(URI 与 {layer} 模板路径重合,
// 精确匹配优先)。这条测试同时兜住 embed 指令:裸 `//go:embed resources/schema` 会静默
// 跳过 `_` 前缀文件,导致本资源在运行期 404 而编译期毫无提示。
func TestResourceSchemaConventions(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	tc := readResource(t, srv, "pmaker://schema/_conventions")
	for _, want := range []string{"两态", "@file", "payload_hex"} {
		if !strings.Contains(tc.Text, want) {
			t.Errorf("_conventions 应含 %q,得到: %q", want, tc.Text)
		}
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
	srv, _ := newTestServer(t)
	defer srv.Close()

	tc := readResource(t, srv, "pmaker://examples")
	// 内置示例编译期 embed,任何 workdir 下都能读出;抽查几个真实存在的条目。
	for _, want := range []string{"http/get.yaml", "dns/query_a.yaml", "icmp/echo.yaml"} {
		if !strings.Contains(tc.Text, want) {
			t.Errorf("examples 应列 %s,得到: %q", want, tc.Text)
		}
	}
	// 描述来自示例首行注释(如 examples/http/get.yaml 首行 "# examples/http/get.yaml" 之后
	// 紧跟描述行,embeddedExampleDescription 取首个非空注释行)。
	if tc.Text == "(无示例)\n" {
		t.Errorf("examples 不应为空,内置示例已被 embed: %q", tc.Text)
	}
}

func TestResourceExampleFile(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	// 读一个真实内置示例,确认原样返回 embed 内容。
	tc := readResource(t, srv, "pmaker://examples/icmp/echo.yaml")
	if !strings.HasPrefix(tc.Text, "#") {
		t.Errorf("示例正文应以注释开头,得到前 80 字: %q", tc.Text[:min(80, len(tc.Text))])
	}
	if !strings.Contains(tc.Text, "link_type:") {
		t.Errorf("示例正文应是 YAML 场景,得到: %q", tc.Text)
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

// ---------- examples 资源:embed 化后的行为 ----------

func TestResourceExamplesListNonEmpty(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()
	// embed 化后 examples 永远非空(内置示例随二进制分发),不再有"无 examples 目录"分支。
	tc := readResource(t, srv, "pmaker://examples")
	if strings.Contains(tc.Text, "无 examples") || strings.Contains(tc.Text, "(无示例)") {
		t.Errorf("embed 化后 examples 不应为空提示,得到: %q", tc.Text)
	}
}

func TestResourceExampleFileMissing(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()
	// 示例走 embed.FS,nope.yaml 不在 embed 树里 → ReadFile 失败。
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
	// 非层文档全部被排除:通则(overview / _conventions)与子结构(multipart)
	// 都有 .md 却不能写进 stack,混进 404 提示会诱导模型写出必然被拒的 YAML。
	for _, notLayer := range []string{"overview", "_conventions", "multipart"} {
		if slices.Contains(got, notLayer) {
			t.Errorf("%q 不是层,不应列入可用层名", notLayer)
		}
	}
	// 应含已知层(含 payload_hex 这类标量层)。
	for _, want := range []string{"eth", "tcp", "dns", "payload_hex"} {
		if !slices.Contains(got, want) {
			t.Errorf("listEmbeddedLayers 应含 %q", want)
		}
	}
	// 应按字典序。
	if !slices.IsSorted(got) {
		t.Errorf("listEmbeddedLayers 应按字典序,得到 %v", got)
	}
}

// ---------- firstCommentDescription ----------
// exampleDescription 原是从磁盘读 YAML 取首行注释;embed 化后拆出纯函数
// firstCommentDescription,解析逻辑不变,直接喂字节测试,不再依赖磁盘文件。

func TestFirstCommentDescription(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"首行注释", "# 一次 HTTP GET\nlink_type: ethernet\n", "一次 HTTP GET"},
		{"前导空行+注释", "\n\n  # 描述\nlink_type: ethernet\n", "描述"},
		{"首个非空行非注释→空", "link_type: ethernet\n", ""},
		{"空行后非注释→空", "\nlink_type: ethernet\n", ""},
		{"空串→空", "", ""},
	}
	for _, c := range cases {
		if got := firstCommentDescription([]byte(c.body)); got != c.want {
			t.Errorf("%s: firstCommentDescription = %q, 期望 %q", c.name, got, c.want)
		}
	}
}
