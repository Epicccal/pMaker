package scenario

import "fmt"

// 本文件定义软告警(非硬错)的统一载体 Diagnostic。异常表达只有两套模型:
//
//   - 硬错:Validate 返回 error(带字段路径),失败即中止;
//   - 软告警:[]Diagnostic,由 scenario 各 Check* 产出,CLI 渲染为 stderr 文本、
//     MCP 渲染为结构化 warnings;
//   - internal/ 内禁止用 slog 打用户可见诊断 —— 日志不回流调用方,MCP(stdio)下
//     模型看不到(由 diagnostic_test.go 的守卫测试锁定);进度/调试日志只放 cmd/ 层。
//
// Severity 不设字段:只有软告警一个级别,级别由通道本身表达
// (error = 硬错,Diagnostic = 软告警);出现第三个级别时再引入,避免投机性枚举。

// Diagnostic 是一条软告警的结构化载体:照常出包,只提示配置可能不自洽,
// 供用户复核(畸形用例可能故意构造不一致,故只告警不阻断)。
type Diagnostic struct {
	// Code 是稳定的机器可读标识符(如 "multipart.boundary-collision"),
	// 命名规范 "<协议或域>.<问题>"(kebab-case)。一经发布即为对外契约,
	// MCP 客户端可能按 code 程序化匹配,只能新增、不能改名。
	Code string `json:"code"`
	// Path 是声明级字段路径(机器可读),文法:
	//   packets[<声明序>].stack[<层序>][.<字段或子结构路径>]
	//   flows[<声明序>].stack[<层序>][.…]                      — flow 模板栈
	//   flows[<声明序>].messages[<消息序>].stack[<层序>][.…]
	// 嵌套子结构追加路径段,如 .multipart.parts[1].body、.literal.eml.multipart。
	// flow 用声明序而非名字定位(名字可空、仅被引用时要求唯一);
	// 人读定位(flow 名或 packet 下标)仍嵌在 Message 文案里。
	Path string `json:"path"`
	// Message 是人读文案(含定位与改法提示),单独渲染即自足。
	Message string `json:"message"`
}

// String 渲染为人读单行文本(即 Message),供 CLI/stderr 直接输出。
func (d Diagnostic) String() string { return d.Message }

// Diagnostic Code 常量表:单一真相源。Check* 与 builder 经 warnf 引用;
// cmd/pmaker-mcp 的 doc-sync 测试以本表锁定「schema 文档承诺的告警 ⇄ 实现」双向同步。
const (
	CodeFTPNegotiationParse = "ftp.negotiation-parse" // 227/229/EPRT 协商文本未解析出端点,无法校验
	CodeFTPPortMismatch     = "ftp.port-mismatch"     // 协商端点与数据流 dst IP:port 不一致
	CodeFTPRoleMismatch     = "ftp.role-mismatch"     // 协商地址与控制连接角色不匹配

	CodeMultipartMissingContentType = "multipart.missing-content-type"   // 父层缺 Content-Type 头
	CodeMultipartBoundaryParamMiss  = "multipart.boundary-param-missing" // Content-Type 未带 boundary= 参数
	CodeMultipartBoundaryMismatch   = "multipart.boundary-mismatch"      // boundary 声明与实际不一致
	CodeMultipartCTEMissing         = "multipart.cte-missing"            // part encoding 非 none 但缺 CTE 头
	CodeMultipartCTEMismatch        = "multipart.cte-mismatch"           // part encoding 与 CTE 头不符
	CodeMultipartBoundaryCollision  = "multipart.boundary-collision"     // part body 内出现独占一行的 boundary 分界符

	CodeHTTPCodingHeaderMissing  = "http.coding-header-missing"   // 声明了 TE/CE 但缺对应头
	CodeHTTPCodingHeaderMismatch = "http.coding-header-mismatch"  // TE/CE 列表与对应头文本不符
	CodeHTTPCLTEConflict         = "http.cl-te-conflict"          // CL 头与 transfer_encoding 并存(走私特征)
	CodeHTTPChunkedNotLast       = "http.chunked-not-last"        // transfer_encoding 中 chunked 不在末位
	CodeHTTPChunkedDuplicate     = "http.chunked-duplicate"       // transfer_encoding 含多个 chunked
	CodeHTTPStatusBodyForbidden  = "http.status-body-forbidden"   // 1xx/204 带 body 且 auto_content_length=true
	CodeHTTP304AutoCL            = "http.304-auto-content-length" // 304 且 auto_content_length=true

	CodeIMAPLiteralOctetsMismatch = "imap.literal-octets-mismatch" // literal.octets 显式值与实际字节数不符

	CodeFlowOverrideStatic = "flow.override-static" // flow.stack 的派生量覆盖(length/checksum/gre.seq/gre.ack)每包同值而真值逐包变

	CodeUDPStreamAppLayer = "udp.stream-app-layer" // UDP 会话的 message.stack 含 TCP 流式协议层

	CodeIPv4MTUBelowMinimum = "ipv4.mtu-below-minimum" // ipv4 mtu 低于 RFC 791 最小 MTU 68
	CodeIPv6MTUBelowMinimum = "ipv6.mtu-below-minimum" // ipv6 mtu 低于 RFC 8200 最小链路 MTU 1280

	CodeTFTPRQPort       = "tftp.rq-port"       // RRQ/WRQ 目标端口不是 69
	CodeTFTPModeObsolete = "tftp.mode-obsolete" // mode = mail 已废弃(RFC 1350 Appendix II)
	CodeTFTPModeUnknown  = "tftp.mode-unknown"  // mode 不在已知集合(octet/netascii/mail)
	CodeTFTPDataOversize = "tftp.data-oversize" // DATA 超过 block_size/512 上限
	CodeTFTPFieldIgnored = "tftp.field-ignored" // opcode 无关字段出现在 YAML 里

	CodeGREReservedNonzero = "gre.reserved-nonzero"  // 保留位/保留字段非零(recursion/flags/offset)
	CodeGREVersionUnknown  = "gre.version-unknown"   // version ∈ 2-7(RFC 2784 只认 0,2637 扩展是 1)
	CodeGREPPTPMissingKey  = "gre.pptp-missing-key"  // version=1(PPTP)未写 key(RFC 2637 §4.1)
	CodeGREAckOutsideV1    = "gre.ack-outside-v1"    // version≠1 时写 ack(A 位仅 RFC 2637 定义)
	CodeGRENVGEMissingKey  = "gre.nvgre-missing-key" // 显式 protocol=0x6558(NVGRE)未写 key(RFC 7637)
)

// WarningCodes 返回全部告警 code(与上方常量表同序维护),供 cmd/pmaker-mcp 的 doc-sync 测试锁定
// 「schema 文档承诺的告警 ⇄ 实现」双向同步。**与上方常量表同步维护**:新增 Code 常量时
// 必须同时加进本切片,否则新告警不会被迫写进文档(doc-sync 测试按本切片驱动)。
func WarningCodes() []string {
	return []string{
		CodeFTPNegotiationParse,
		CodeFTPPortMismatch,
		CodeFTPRoleMismatch,
		CodeMultipartMissingContentType,
		CodeMultipartBoundaryParamMiss,
		CodeMultipartBoundaryMismatch,
		CodeMultipartCTEMissing,
		CodeMultipartCTEMismatch,
		CodeMultipartBoundaryCollision,
		CodeHTTPCodingHeaderMissing,
		CodeHTTPCodingHeaderMismatch,
		CodeHTTPCLTEConflict,
		CodeHTTPChunkedNotLast,
		CodeHTTPChunkedDuplicate,
		CodeHTTPStatusBodyForbidden,
		CodeHTTP304AutoCL,
		CodeIMAPLiteralOctetsMismatch,
		CodeFlowOverrideStatic,
		CodeUDPStreamAppLayer,
		CodeIPv4MTUBelowMinimum,
		CodeIPv6MTUBelowMinimum,
		CodeTFTPRQPort,
		CodeTFTPModeObsolete,
		CodeTFTPModeUnknown,
		CodeTFTPDataOversize,
		CodeTFTPFieldIgnored,
		CodeGREReservedNonzero,
		CodeGREVersionUnknown,
		CodeGREPPTPMissingKey,
		CodeGREAckOutsideV1,
		CodeGRENVGEMissingKey,
	}
}

// warnf 构造一条软告警 Diagnostic。code 用上表常量,path 按字段路径文法,
// format/args 产出人读文案。
func warnf(code, path, format string, args ...any) Diagnostic {
	return Diagnostic{Code: code, Path: path, Message: fmt.Sprintf(format, args...)}
}

// packetStackPath 拼 standalone packet 层的字段路径:packets[i].stack[j]。
func packetStackPath(i, j int) string {
	return fmt.Sprintf("packets[%d].stack[%d]", i, j)
}

// flowStackPath 拼flow 模板栈层的字段路径:flows[i].stack[j]。
func flowStackPath(i, j int) string {
	return fmt.Sprintf("flows[%d].stack[%d]", i, j)
}

// flowMessageStackPath 拼flow 消息层栈的字段路径:flows[i].messages[k].stack[j]。
func flowMessageStackPath(i, k, j int) string {
	return fmt.Sprintf("flows[%d].messages[%d].stack[%d]", i, k, j)
}

// flowMessagePath 拼flow 消息级的字段路径:flows[i].messages[k]。
func flowMessagePath(i, k int) string {
	return fmt.Sprintf("flows[%d].messages[%d]", i, k)
}
