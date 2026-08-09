// Command pmaker-mcp 把 pMaker 的核心能力(生成场景 YAML、生成 pcap)暴露成 MCP server,
// 供支持 MCP 的客户端(其他大模型)调用。走 stdio transport。
//
// 用法:
//
//	pmaker-mcp -workdir <场景工作目录>
//	# 或环境变量 PMAKER_WORKDIR(缺省 = 当前工作目录)
//
// workdir 下自动创建 yaml/、pcap/ 两个子目录,分别存放 generate_yaml / generate_pcap 的产物。
// 复用 internal/scenario|plan|builder|writer 现有链路,不改动 CLI 行为。
// 详见仓库根 CLAUDE.md 与设计文档。
package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// version 由构建时 -ldflags 注入,默认 "dev"。
var version = "dev"

//go:embed resources/schema
var schemaFS embed.FS

const schemaMIME = "text/markdown"

func main() {
	workdir := flag.String("workdir", envOr("PMAKER_WORKDIR", ""), "场景工作目录(@file 相对路径相对它解析;其下自动建 yaml/ pcap/ 子目录存放生成产物)")
	flag.Parse()

	if *workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintln(os.Stderr, "pmaker-mcp: 获取工作目录:", err)
			os.Exit(1)
		}
		*workdir = wd
	}
	// 解析为绝对路径(输出路径校验、摘要里都好引用)。
	absWorkdir, err := filepath.Abs(*workdir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pmaker-mcp: 解析 workdir:", err)
		os.Exit(1)
	}
	// 在 workdir 下自动建 yaml/、pcap/ 两个子目录,分别存放 generate_yaml / generate_pcap 的产物。
	yamlDir := filepath.Join(absWorkdir, "yaml")
	pcapDir := filepath.Join(absWorkdir, "pcap")
	for _, d := range []string{yamlDir, pcapDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			fmt.Fprintf(os.Stderr, "pmaker-mcp: 创建目录 %s: %v\n", d, err)
			os.Exit(1)
		}
	}

	cfg := config{workdir: absWorkdir, yamlDir: yamlDir, pcapDir: pcapDir}

	srv := server.NewMCPServer("pmaker-mcp", version,
		server.WithToolCapabilities(true),
		// subscribe=false(不支持资源订阅);listChanged=false:资源在启动时一次性注册,
		// 运行期不变,不发送 notifications/resources/list_changed。
		server.WithResourceCapabilities(false, false),
	)
	srv.AddTool(generateYAMLTool(), cfg.handleGenerateYAML)
	srv.AddTool(generatePcapTool(), cfg.handleGeneratePcap)
	cfg.registerResources(srv)

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, "pmaker-mcp:", err)
		os.Exit(1)
	}
}

// envOr 返回环境变量值,空则返回 fallback。
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// config 在 server 生命周期内不变,作为 handler 的闭包状态。
type config struct {
	workdir string // @file 相对路径的基准目录;其下有 yaml/ pcap/ 子目录
	yamlDir string // generate_yaml 产物落盘目录(= workdir/yaml,绝对路径)
	pcapDir string // generate_pcap 产物落盘目录(= workdir/pcap,绝对路径)
}

// ---------- 通用入参 ----------

// toolInput 是两个工具共用的入参(YAML 文本 + 输出文件名),字段完全相同。
// bindToolInput 统一完成反序列化与参数校验,避免在两个 handler 里各写一遍。
type toolInput struct {
	YAML       string `json:"yaml"`
	OutputName string `json:"output_name"`
}

// bindToolInput 反序列化入参并做非空 + 路径穿越 + 扩展名校验。
// ext 是该工具要求 output_name 必须带的后缀(如 ".yaml" / ".pcap")。
// 参数错误返回 MCP 协议 error(调用本身不成立),与业务校验失败区分。
func bindToolInput(req mcp.CallToolRequest, ext string) (toolInput, error) {
	var in toolInput
	if err := req.BindArguments(&in); err != nil {
		return in, fmt.Errorf("解析参数: %w", err)
	}
	if in.YAML == "" {
		return in, fmt.Errorf("参数 yaml 不能为空")
	}
	if in.OutputName == "" {
		return in, fmt.Errorf("参数 output_name 不能为空")
	}
	if err := validateOutputName(in.OutputName); err != nil {
		return in, err
	}
	if !strings.HasSuffix(in.OutputName, ext) {
		return in, fmt.Errorf("参数 output_name 必须以 %q 结尾: %q", ext, in.OutputName)
	}
	return in, nil
}

// ---------- tool: generate_yaml ----------

// generateYAMLOutput 是 generate_yaml 的结构化输出。
type generateYAMLOutput struct {
	Valid    bool     `json:"valid"`
	Path     string   `json:"path,omitempty"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func generateYAMLTool() mcp.Tool {
	return mcp.NewTool("generate_yaml",
		mcp.WithDescription(
			"校验并归档 pMaker 场景 YAML:校验通过则把 YAML 落盘到 workdir/yaml/(便于归档/复现/给非开发者查看),"+
				"返回 valid=true 与落盘路径;校验失败不落盘,返回 valid=false + 结构化 errors(每个带字段路径,"+
				"如 \"packet[2].stack[1].vlan: vid 缺失\"),供调用方据以修正后重试。"+
				"这是写场景 YAML 的主入口:你(模型)自行编写 YAML,本工具负责校验合法性并归档。"+
				"如不熟悉 YAML 语法,先读 resource pmaker://schema 与 pmaker://examples。"),
		mcp.WithString("yaml",
			mcp.Required(),
			mcp.Description("场景 YAML 文本(完整文件内容,由调用方编写)")),
		mcp.WithString("output_name",
			mcp.Required(),
			mcp.Description("归档文件名(仅文件名,如 \"http-get.yaml\";不含目录或路径分隔符;必须以 .yaml 结尾)")),
	)
}

func (c config) handleGenerateYAML(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	in, err := bindToolInput(req, ".yaml")
	if err != nil {
		return nil, err
	}

	out := generateYAMLOutput{Valid: true}

	// 解析 + 语义校验 + 软告警(校验逻辑与 generate_pcap 共用,保证两工具一致)。
	// 校验失败:Valid=false + isError=true + errors,与 generate_pcap 语义一致。
	s, err := scenario.Parse([]byte(in.YAML), c.workdir)
	if err != nil {
		out.Valid = false
		out.Errors = []string{err.Error()}
		return marshalResult(out, true)
	}
	if verr := scenario.Validate(s); verr != nil {
		out.Valid = false
		out.Errors = []string{verr.Error()}
		return marshalResult(out, true)
	}
	out.Warnings = scenario.Warnings(s)

	// 校验通过才落盘到 workdir/yaml/(原样写入入参 YAML,不做规范化改写)。
	outPath := filepath.Join(c.yamlDir, in.OutputName)
	if err := os.WriteFile(outPath, []byte(in.YAML), 0o600); err != nil {
		// 校验已过,写盘属执行层故障:Valid 保持 true,走结构化 isError=true,
		// 与 generate_pcap 执行层故障(时间编排/构包/写盘)语义一致。
		out.Errors = []string{fmt.Sprintf("写盘: %v", err)}
		return marshalResult(out, true)
	}
	out.Path = outPath

	return marshalResult(out, false)
}

// ---------- tool: generate_pcap ----------

// generatePcapOutput 是 generate_pcap 的结构化输出。
// Valid 与 generate_yaml 对齐:校验通过=true、失败=false。失败时 isError 也=true、
// Path/YAMLPath/Summary 留空,客户端可据 Valid 或 isError 判断是否拿到 pcap。
type generatePcapOutput struct {
	Valid       bool     `json:"valid"`
	Path        string   `json:"path,omitempty"`
	YAMLPath    string   `json:"yaml_path,omitempty"`
	PacketCount int      `json:"packet_count"`
	Summary     []string `json:"summary,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	// 校验失败时填充(不写文件),供调用方据以修正。
	Errors []string `json:"errors,omitempty"`
}

func generatePcapTool() mcp.Tool {
	return mcp.NewTool("generate_pcap",
		mcp.WithDescription(
			"校验场景 YAML 并生成 pcap 文件(离线、不发包)。"+
				"与 generate_yaml 共用同一套校验逻辑:校验失败不写文件,返回 errors 清单(带字段路径);"+
				"成功返回 pcap 路径、包数与每包摘要,并在 yaml/ 目录同步归档同名场景 YAML(仅扩展名不同)。"+
				"output_name 仅文件名(不含路径,防路径穿越),文件落到 server 配置的 workdir/pcap/。"+
				"如不熟悉 YAML 语法,先读 resource pmaker://schema 与 pmaker://examples。"),
		mcp.WithString("yaml",
			mcp.Required(),
			mcp.Description("场景 YAML 文本(完整文件内容)")),
		mcp.WithString("output_name",
			mcp.Required(),
			mcp.Description("输出 pcap 文件名(仅文件名,如 \"out.pcap\";不含目录或路径分隔符;必须以 .pcap 结尾)")),
	)
}

func (c config) handleGeneratePcap(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	in, err := bindToolInput(req, ".pcap")
	if err != nil {
		return nil, err
	}

	out := generatePcapOutput{}

	// 两个正交维度:
	//   - Valid:YAML 是否通过 Parse+Validate(输入质量)。
	//   - isError:本次调用是否成功产出 pcap(整体结果)。
	// 校验失败 → Valid=false, isError=true(输入问题);
	// 校验通过但执行层(时间编排/构包/写盘)失败 → Valid=true, isError=true(输入合法,内部故障);
	// 全程成功 → Valid=true, isError=false。
	s, err := scenario.Parse([]byte(in.YAML), c.workdir)
	if err != nil {
		out.Errors = []string{err.Error()}
		return marshalResult(out, true) // 校验失败:Valid=false, isError=true
	}
	if verr := scenario.Validate(s); verr != nil {
		out.Errors = []string{verr.Error()}
		return marshalResult(out, true) // 校验失败:Valid=false, isError=true
	}
	out.Valid = true
	out.Warnings = scenario.Warnings(s)

	// 时间编排 -> 构包 -> 写盘。以下任一失败:Valid 仍为 true(校验已过),isError=true。
	planned, err := plan.Plan(s)
	if err != nil {
		out.Errors = []string{fmt.Sprintf("时间编排: %v", err)}
		return marshalResult(out, true) // 执行层故障:Valid=true, isError=true
	}
	pkts, err := builder.BuildPlanned(planned)
	if err != nil {
		out.Errors = []string{fmt.Sprintf("构包: %v", err)}
		return marshalResult(out, true) // 执行层故障:Valid=true, isError=true
	}

	// 写盘:pcap 落 pcap/,同名 YAML 落 yaml/(便于对照复现)。
	outPath := filepath.Join(c.pcapDir, in.OutputName)
	if err := writer.Write(outPath, s.LinkType, pkts); err != nil {
		out.Errors = []string{fmt.Sprintf("写盘: %v", err)}
		return marshalResult(out, true) // 执行层故障:Valid=true, isError=true
	}
	yamlName := strings.TrimSuffix(in.OutputName, filepath.Ext(in.OutputName)) + ".yaml"
	yamlPath := filepath.Join(c.yamlDir, yamlName)
	if err := os.WriteFile(yamlPath, []byte(in.YAML), 0o600); err != nil {
		out.Warnings = append(out.Warnings, fmt.Sprintf("归档 YAML 失败: %v", err))
	} else {
		out.YAMLPath = yamlPath
	}

	out.Path = outPath
	out.PacketCount = len(pkts)
	out.Summary = scenario.FormatPacketSummaries(scenario.SummarizePlanned(planned))
	return marshalResult(out, false)
}

// validateOutputName 拒绝含路径分隔符或 `..` 段的文件名,防路径穿越。
func validateOutputName(name string) error {
	if name == "" {
		return fmt.Errorf("output_name 不能为空")
	}
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("output_name 只能是文件名,不能含路径分隔符: %q", name)
	}
	if name == ".." || strings.HasPrefix(name, "..") {
		// `..foo` 不是遍历,但 `..` 本身和以 `..` 开头的可疑形式都拒。
		return fmt.Errorf("output_name 不能以 \"..\" 开头: %q", name)
	}
	return nil
}

// ---------- 通用结果封装 ----------

// marshalResult 把结构化输出编进 CallToolResult:
//   - StructuredContent 放原始 JSON(供客户端程序化消费);
//   - Content 放等价的人类可读文本(JSON pretty,供 LLM 阅读)。
//
// 两个正交字段:
//   - Valid:输入 YAML 是否通过 Parse+Validate(输入质量)。校验通过即 true,无论后续执行是否成功。
//   - isError:本次调用是否成功产出产物(文件落盘)。false=成功;true=未产出(校验失败或执行层故障)。
//
// 组合:校验失败→Valid=false,isError=true;校验通过但执行层(时间编排/构包/写盘)失败→Valid=true,isError=true;
// 全程成功→Valid=true,isError=false。客户端可据 isError 判断是否拿到产物,据 Valid 区分输入问题与内部故障。
//
// 与 MCP 协议 error 的区分:协议 error(return error)用于「调用本身不成立」(参数缺失/类型错/
// 路径穿越),由 mcp-go 转成 JSON-RPC error;isError 是「调用成立、返回结构化结果,但结果标记失败」。
func marshalResult(v any, isError bool) (*mcp.CallToolResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("编码结果: %w", err)
	}
	result := &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent(string(data))},
	}
	if isError {
		result.IsError = true
	}
	// StructuredContent 用未缩进的 JSON(程序化消费的标准形式)。
	raw, _ := json.Marshal(v)
	result.StructuredContent = json.RawMessage(raw)
	return result, nil
}

// ---------- resources: 把语法知识带内喂给模型 ----------

// resourceRegistrar 是 MCPServer 与 mcptest.Server 共有的注册接口,
// 让 registerResources 可同时用于生产 server 与测试 server。
type resourceRegistrar interface {
	AddResource(resource mcp.Resource, handler server.ResourceHandlerFunc)
	AddResourceTemplate(template mcp.ResourceTemplate, handler server.ResourceTemplateHandlerFunc)
}

// registerResources 注册 4 个 resource(2 个固定 + 2 个 template)。
// 内容全部来自文件(embed 的 schema 目录 / workdir 的 examples 目录),
// 加协议只需新增 schema/<proto>.md 或 examples/<proto>/*.yaml,Go 代码零改动。
func (c config) registerResources(srv resourceRegistrar) {
	// pmaker://schema —— 语法总览(读 embed 的 overview.md)。
	srv.AddResource(schemaOverviewResource(), c.handleSchemaOverview)
	// pmaker://schema/{layer} —— 单协议字段速查(embed)。
	srv.AddResourceTemplate(schemaLayerTemplate(), c.handleSchemaLayer)
	// pmaker://examples —— 示例清单(动态扫 workdir/examples)。
	srv.AddResource(examplesListResource(), c.handleExamplesList)
	// pmaker://examples/{protocol}/{name} —— 单个示例正文(YAML 原文)。
	srv.AddResourceTemplate(exampleFileTemplate(), c.handleExampleFile)
}

func schemaOverviewResource() mcp.Resource {
	return mcp.NewResource("pmaker://schema", "pMaker 场景语法总览",
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
	data, err := schemaFS.ReadFile("resources/schema/overview.md")
	if err != nil {
		return nil, fmt.Errorf("读取 overview: %w", err)
	}
	return []mcp.ResourceContents{mcp.TextResourceContents{
		URI:      req.Params.URI,
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

// handleExamplesList 扫描 workdir/examples/<协议>/*.yaml,返回清单(协议、文件名、描述)。
func (c config) handleExamplesList(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	root := filepath.Join(c.workdir, "examples")
	entries, err := os.ReadDir(root)
	if err != nil {
		return []mcp.ResourceContents{mcp.TextResourceContents{
			URI:      req.Params.URI,
			MIMEType: "text/plain",
			Text:     "(workdir 下无 examples 目录)\n",
		}}, nil
	}
	var lines []string
	var protos []string
	for _, e := range entries {
		if e.IsDir() {
			protos = append(protos, e.Name())
		}
	}
	sort.Strings(protos)
	for _, proto := range protos {
		files, err := os.ReadDir(filepath.Join(root, proto))
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
				continue
			}
			desc := exampleDescription(filepath.Join(root, proto, f.Name()))
			lines = append(lines, fmt.Sprintf("%s/%s\t%s", proto, f.Name(), desc))
		}
	}
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

// handleExampleFile 按 {protocol}/{name} 读 workdir/examples 下对应 YAML 原文。
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
	path := filepath.Join(c.workdir, "examples", proto, name)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取示例 %s/%s: %w", proto, name, err)
	}
	return []mcp.ResourceContents{mcp.TextResourceContents{
		URI:      req.Params.URI,
		MIMEType: "text/yaml",
		Text:     string(data),
	}}, nil
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

// listEmbeddedLayers 列出 embed 里 schema/ 下可用的层名(去 .md 后缀),按字典序。
func listEmbeddedLayers() []string {
	entries, err := fs.ReadDir(schemaFS, "resources/schema")
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := strings.TrimSuffix(e.Name(), ".md")
		if n != "" && n != "overview" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

// exampleDescription 读取示例 YAML 的首行注释(# …)作描述;无则返回空串。
func exampleDescription(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
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
