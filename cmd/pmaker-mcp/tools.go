package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/summary"
	"github.com/Epicccal/pMaker/internal/writer"
)

// ---------- 通用入参 ----------

// codeArchiveYAMLWriteFailed:generate_pcap 归档场景 YAML 写盘失败的告警 code。
// 执行层故障(非场景不自洽),不在 scenario.WarningCodes 常量表内,但同样是对外契约。
const codeArchiveYAMLWriteFailed = "archive.yaml-write-failed"

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
	Valid    bool                  `json:"valid"`
	Path     string                `json:"path,omitempty"`
	Errors   []string              `json:"errors,omitempty"`
	Warnings []scenario.Diagnostic `json:"warnings,omitempty"`
}

func generateYAMLTool() mcp.Tool {
	return mcp.NewTool("generate_yaml",
		mcp.WithDescription(
			"校验并归档 pMaker 场景 YAML:校验通过则把 YAML 落盘到 workdir/yaml/(便于归档/复现/给非开发者查看),"+
				"返回 valid=true 与落盘路径;校验失败不落盘,返回 valid=false + 结构化 errors(每个带字段路径,"+
				"如 \"packet[2].stack[1].vlan: vid 缺失\"),供调用方据以修正后重试。"+
				"这是写场景 YAML 的主入口:你(模型)自行编写 YAML,本工具负责校验合法性并归档。"+
				"如不熟悉 YAML 语法,先读 resource pmaker://schema、pmaker://schema/_conventions 与 pmaker://examples。"),
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
	Valid       bool                  `json:"valid"`
	Path        string                `json:"path,omitempty"`
	YAMLPath    string                `json:"yaml_path,omitempty"`
	PacketCount int                   `json:"packet_count"`
	Summary     []string              `json:"summary,omitempty"`
	Warnings    []scenario.Diagnostic `json:"warnings,omitempty"`
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
				"如不熟悉 YAML 语法,先读 resource pmaker://schema、pmaker://schema/_conventions 与 pmaker://examples。"),
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
		// 归档失败不影响 pcap 产出,以软告警回传(执行层故障,code 固定便于客户端识别)。
		// Path 留空:它是声明级字段路径文法,执行层故障不指向任何 YAML 字段;
		// 归档文件名只进 Message(避免客户端把 Path 误当字段路径解析)。
		out.Warnings = append(out.Warnings, scenario.Diagnostic{
			Code:    codeArchiveYAMLWriteFailed,
			Message: fmt.Sprintf("归档 YAML %q 失败: %v", yamlName, err),
		})
	} else {
		out.YAMLPath = yamlPath
	}

	out.Path = outPath
	out.PacketCount = len(pkts)
	out.Summary = summary.FormatPacketSummaries(summary.SummarizePlanned(planned))
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
