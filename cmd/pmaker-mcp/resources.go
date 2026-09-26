package main

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/Epicccal/pMaker/examples"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// ---------- resources: 把语法知识带内喂给模型 ----------

// resourceRegistrar 是 MCPServer 与 mcptest.Server 共有的注册接口,
// 让 registerResources 可同时用于生产 server 与测试 server。
type resourceRegistrar interface {
	AddResource(resource mcp.Resource, handler server.ResourceHandlerFunc)
	AddResourceTemplate(template mcp.ResourceTemplate, handler server.ResourceTemplateHandlerFunc)
}

// registerResources 注册 5 个 resource(3 个固定 + 2 个 template)。
// 内容全部来自 embed(schema 目录 + examples 目录),不依赖运行期 workdir;
// 加协议只需新增 schema/<proto>.md 或 examples/<proto>/*.yaml,Go 代码零改动。
func (c config) registerResources(srv resourceRegistrar) {
	// pmaker://schema —— 语法总览(读 embed 的 overview.md)。
	srv.AddResource(schemaOverviewResource(), c.handleSchemaOverview)
	// pmaker://schema/_conventions —— 全局通则(两态覆盖 / @file / Hex / 兜底 / 成帧)。
	// 单独 AddResource 而非只靠 {layer} 模板命中:template 不出现在 MCP resources/list 里,
	// 而通则是「写任意 YAML 前读一次」的东西,模型不该靠猜 URI 才能发现它。
	// URI 与 template 路径重合,mcp-go 精确匹配优先。
	srv.AddResource(schemaConventionsResource(), c.handleSchemaConventions)
	// pmaker://schema/{layer} —— 单协议字段速查(embed)。
	srv.AddResourceTemplate(schemaLayerTemplate(), c.handleSchemaLayer)
	// pmaker://examples —— 示例清单(扫 embed 的 examples 树)。
	srv.AddResource(examplesListResource(), c.handleExamplesList)
	// pmaker://examples/{protocol}/{name} —— 单个示例正文(YAML 原文)。
	srv.AddResourceTemplate(exampleFileTemplate(), c.handleExampleFile)
}

func schemaOverviewResource() mcp.Resource {
	return mcp.NewResource("pmaker://schema", "pMaker 场景语法总览",
		mcp.WithMIMEType(schemaMIME),
	)
}

func schemaConventionsResource() mcp.Resource {
	return mcp.NewResource("pmaker://schema/_conventions", "pMaker 全局通则",
		mcp.WithResourceDescription("两态覆盖 / @file / Hex / 原始字节兜底 / 成帧总则,写任意场景 YAML 前读一次"),
		mcp.WithMIMEType(schemaMIME),
	)
}

func schemaLayerTemplate() mcp.ResourceTemplate {
	return mcp.NewResourceTemplate("pmaker://schema/{layer}", "pMaker 单层语法",
		mcp.WithTemplateDescription("某协议层(eth/ipv4/tcp/dns/…)的字段速查"),
		mcp.WithTemplateMIMEType(schemaMIME),
	)
}

func examplesListResource() mcp.Resource {
	return mcp.NewResource("pmaker://examples", "pMaker 示例清单",
		mcp.WithMIMEType("text/plain"),
	)
}

func exampleFileTemplate() mcp.ResourceTemplate {
	return mcp.NewResourceTemplate("pmaker://examples/{protocol}/{name}", "pMaker 单个示例",
		mcp.WithTemplateDescription("某协议下一个示例场景的 YAML 原文"),
		mcp.WithTemplateMIMEType("text/yaml"),
	)
}

// handleSchemaOverview 返回 embed 的 overview.md。
func (c config) handleSchemaOverview(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	return embeddedSchemaDoc(req.Params.URI, "overview")
}

// handleSchemaConventions 返回 embed 的 _conventions.md(全局通则)。
func (c config) handleSchemaConventions(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	return embeddedSchemaDoc(req.Params.URI, "_conventions")
}

// embeddedSchemaDoc 读 embed 的 schema/<name>.md 并包装成 resource contents。
// name 由调用方给定(非用户输入),故不需要再过 isSafeName。
func embeddedSchemaDoc(uri, name string) ([]mcp.ResourceContents, error) {
	data, err := schemaFS.ReadFile("resources/schema/" + name + ".md")
	if err != nil {
		return nil, fmt.Errorf("读取 %s: %w", name, err)
	}
	return []mcp.ResourceContents{mcp.TextResourceContents{
		URI:      uri,
		MIMEType: schemaMIME,
		Text:     string(data),
	}}, nil
}

// handleSchemaLayer 按 {layer} 参数读 embed 的 schema/<layer>.md。
func (c config) handleSchemaLayer(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	layer := templateArg(req, "layer")
	if layer == "" {
		return nil, fmt.Errorf("缺少 {layer} 参数")
	}
	// 兼容带 .md 后缀的写法:URI 规范是裸层名(pmaker://schema/http_request),但调用端
	// 模型常按磁盘文件名类推补上 .md。剥掉后缀再走 isSafeName,校验口径不变。
	layer = strings.TrimSuffix(layer, ".md")
	if !isSafeName(layer) {
		return nil, fmt.Errorf("未知层名 %q", layer)
	}
	data, err := schemaFS.ReadFile("resources/schema/" + layer + ".md")
	if err != nil {
		available := listEmbeddedLayers()
		return nil, fmt.Errorf("未知层 %q,可用:%s", layer, strings.Join(available, ", "))
	}
	return []mcp.ResourceContents{mcp.TextResourceContents{
		URI:      req.Params.URI,
		MIMEType: schemaMIME,
		Text:     string(data),
	}}, nil
}

// handleExamplesList 列出 embed 的内置示例(examples/<协议>/*.yaml),返回清单(协议、文件名、描述)。
// examples 编译期 embed 进二进制(见 examples/examples.go 的 `all:*`),故**不依赖 workdir**:
// 无论 server 以哪个 workdir 启动,模型都能读到与当前二进制同版本的内置示例。
//
// examples.FS 的根是 examples/ 包目录本身,所以路径是 "dns/query_a.yaml" 而非
// "examples/dns/query_a.yaml";本函数枚举顶层目录即得到协议列表。
func (c config) handleExamplesList(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	entries, err := fs.ReadDir(examples.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("读取内置示例清单: %w", err)
	}
	var lines []string
	var protos []string
	for _, e := range entries {
		// 跳过非目录(如 examples.go 本身、assets 散文件);只收顶层协议目录。
		if !e.IsDir() {
			continue
		}
		protos = append(protos, e.Name())
	}
	sort.Strings(protos)
	for _, proto := range protos {
		files, err := fs.ReadDir(examples.FS, proto)
		if err != nil {
			continue // embed 树内不该发生;防御性跳过
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
				continue // 跳过 assets/ 子目录与非 .yaml 文件
			}
			desc := embeddedExampleDescription(proto, f.Name())
			lines = append(lines, fmt.Sprintf("%s/%s\t%s", proto, f.Name(), desc))
		}
	}
	sort.Strings(lines) // 清单整体按协议|文件名排序,输出确定性可复现
	text := "(无示例)\n"
	if len(lines) > 0 {
		text = strings.Join(lines, "\n") + "\n"
	}
	return []mcp.ResourceContents{mcp.TextResourceContents{
		URI:      req.Params.URI,
		MIMEType: "text/plain",
		Text:     text,
	}}, nil
}

// handleExampleFile 按 {protocol}/{name} 读 embed 的内置示例 YAML 原文(不依赖 workdir)。
func (c config) handleExampleFile(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	proto := templateArg(req, "protocol")
	name := templateArg(req, "name")
	// 强制 .yaml 后缀,与 handleExamplesList(只列 .yaml)对齐:
	// 否则无后缀名(如 README)会通过 isSafeName 被当作示例读出,与 resource 语义不符。
	if !strings.HasSuffix(name, ".yaml") {
		return nil, fmt.Errorf("示例名必须以 .yaml 结尾: %q", name)
	}
	if !isSafeName(proto) || !isSafeName(strings.TrimSuffix(name, ".yaml")) {
		return nil, fmt.Errorf("非法协议或示例名: %q/%q", proto, name)
	}
	// examples.FS 根是 examples/ 包目录,路径是 "<proto>/<name>" 而非 "examples/<proto>/<name>"。
	// 用 path.Join 而非 filepath.Join:embed.FS 的路径键永远用正斜杠(即使 Windows 上),
	// filepath.Join 在 Windows 会用反斜杠拼接,导致 embed.FS.Open 找不到文件。
	data, err := fs.ReadFile(examples.FS, path.Join(proto, name))
	if err != nil {
		return nil, fmt.Errorf("读取示例 %s/%s: %w", proto, name, err)
	}
	return []mcp.ResourceContents{mcp.TextResourceContents{
		URI:      req.Params.URI,
		MIMEType: "text/yaml",
		Text:     string(data),
	}}, nil
}

// embeddedExampleDescription 读取 embed 示例 YAML 的首行注释(# …)作描述;无则返回空串。
func embeddedExampleDescription(proto, name string) string {
	// 同上,embed.FS 路径用正斜杠,须用 path.Join。
	data, err := fs.ReadFile(examples.FS, path.Join(proto, name))
	if err != nil {
		return ""
	}
	return firstCommentDescription(data)
}

// firstCommentDescription 返回 YAML 正文首个非空注释行(# …)的内容;无则返回空串。
// 纯函数,便于独立测试(embed 化前从磁盘读,化后从 embed.FS 读,解析逻辑不变)。
func firstCommentDescription(data []byte) string {
	for line := range strings.SplitSeq(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(trimmed, "#"); ok {
			return strings.TrimSpace(rest)
		}
		return ""
	}
	return ""
}

// templateArg 从 resource template 的 URI 参数里取值。
// mcp-go 把 URI 模板匹配后的参数放进 req.Params.Arguments(map[string]any),
// 值为 []string(每段一个),取第一个即可。
func templateArg(req mcp.ReadResourceRequest, key string) string {
	args := req.Params.Arguments
	if args == nil {
		return ""
	}
	v, ok := args[key]
	if !ok {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case []string:
		if len(val) > 0 {
			return val[0]
		}
	}
	return ""
}

// isSafeName 校验层名/协议名/示例名:仅字母数字下划线与连字符,防路径穿越。
func isSafeName(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// listEmbeddedLayers 列出可作为 `pmaker://schema/{layer}` 推荐值的**真实层名**,按字典序。
//
// 只取「既是 scenario 合法层名、又有 embed 文档」的交集:schema/ 下还躺着 overview、
// _conventions 等通则文档与 multipart 这类子结构文档,它们不是层、不能写进 stack,
// 若混进 404 提示会诱导模型写出 `- multipart: {...}` 这种必然被拒的 YAML。
// 交集口径也免去了在此维护第二份「非层文档」名单——层名以 scenario.LayerTypes() 为准。
func listEmbeddedLayers() []string {
	entries, err := fs.ReadDir(schemaFS, "resources/schema")
	if err != nil {
		return nil
	}
	isLayer := make(map[string]bool, len(scenario.LayerTypes()))
	for _, n := range scenario.LayerTypes() {
		isLayer[n] = true
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := strings.TrimSuffix(e.Name(), ".md")
		if isLayer[n] {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}
