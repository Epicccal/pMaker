// Package scenario 定义声明式场景文件(YAML)的 schema、解析与校验。
//
// 每个 packet 是一个从外到内的有序 layer 栈(见 CLAUDE.md「封装与隧道」),
// 允许同类型重复(QinQ 双 VLAN)与递归嵌套(GRE 套报文)。
// 校验须尽早失败,报错带字段路径,便于非开发者定位问题。
//
// 时间表达采用「base_time + offset_time」模型:base_time 是场景里唯一的绝对锚
// (AbsTime,仅 ISO8601),packet.offset_time / flow.offset_time 是相对它的时长
// 偏移(Offset,仅接受时长)。两者由各自类型在解析阶段结构性保证取值合法,
// 不再依赖运行期校验兜底。PlannedPacket 是 scenario 模型 + 显式时间戳的中间态,
// 由 internal/plan 汇流排序后交 builder 序列化。
//
// 文件组织:
//   - types.go:              顶层结构体(Scenario/FlowSpec/Message/...)与基础类型(Hex/PayloadHex 解析)。
//   - time.go:               AbsTime / Offset 时间类型及其 YAML 解析。
//   - layer_fields.go:       各协议层的字段结构体(*Fields)与子结构(MultipartBody/MultipartPart)。
//   - layer_decode.go:       Layer.UnmarshalYAML 与按类型分发解码、未知字段校验。
//   - header_map.go:         HeaderMap 有序键值集合(保序、可重复键,供 HTTP/EML/SMTP 等头部使用)。
//   - http_validate.go:     HTTP 请求/响应字段结构与校验。
//   - scenario.go:           Load / Validate / Warnings 等对外入口与语义校验。
//   - start_after_graph.go:  start_after 依赖图(校验与 plan 算时共用)。
//   - file_placeholder.go:   @file(...) 占位符替换,反射遍历 Scenario 全部 string 字段。
//   - ftp_command.go:        FTP 命令/响应码合法基线校验(RFC 959 + 扩展)。
//   - ftp_consistency.go:    FTP 控制通道 ↔ 数据通道端口一致性告警(227/PORT/229/EPRT)。
//   - telnet_command.go:     TELNET 命令/option 合法基线校验(RFC 854 + 扩展)。
//   - smtp_command.go:       SMTP 信封 verb / 响应码合法基线校验(RFC 5321 + 扩展)。
//   - pop3_command.go:       POP3 命令 / 状态指示符合法基线校验(RFC 1939 + 扩展)。
//   - eml_data.go:           RFC 5322 正文层校验(协议无关,SMTP/POP3/IMAP 共用)。
//   - multipart.go:          MIME multipart 校验 + boundary 校验(RFC 2046)。
//   - multipart_consistency.go: multipart boundary/CTE 一致性告警。
//   - summary_layers.go:    摘要展示用的层名白名单(SummaryLayerNames,schema 元信息,
//     供 internal/summary 与 flow 包调用)。
package scenario
