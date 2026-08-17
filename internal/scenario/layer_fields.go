package scenario

import "gopkg.in/yaml.v3"

// 各层字段结构。指针字段表示"可选/是否显式给出"。
type (
	EthFields struct {
		Src       string `yaml:"src"`
		Dst       string `yaml:"dst"`
		EtherType *Hex   `yaml:"ethertype"`
	}
	VLANFields struct {
		VID  uint16 `yaml:"vid"`
		TPID *Hex   `yaml:"tpid"` // 后一个 VLAN 标签的 TPID(next==vlan 时映射到 Dot1Q.Type)
		Type *Hex   `yaml:"type"` // 显式覆盖 next-proto(制造断链)
	}
	IPv4Fields struct {
		Src      string  `yaml:"src"`
		Dst      string  `yaml:"dst"`
		TTL      *uint8  `yaml:"ttl"`
		Protocol *string `yaml:"protocol"` // 覆盖:tcp/udp/gre/ipv4
		// 畸形开关:当前解析但构建时忽略并告警。
		Checksum   *Hex  `yaml:"checksum"`
		FixLengths *bool `yaml:"fix_lengths"`
	}
	IPv6Fields struct {
		Src          string  `yaml:"src"`
		Dst          string  `yaml:"dst"`
		HopLimit     *uint8  `yaml:"hop_limit"` // 跳数限制(类比 IPv4 ttl),缺省 64
		TrafficClass *uint8  `yaml:"traffic_class"`
		FlowLabel    *uint32 `yaml:"flow_label"`
		NextHeader   *string `yaml:"next_header"` // 覆盖:tcp/udp/icmpv6/ipv4/ipv6(制造断链)
	}
	GREFields struct{}
	TCPFields struct {
		SPort     uint16   `yaml:"sport"`
		DPort     uint16   `yaml:"dport"`
		Flags     []string `yaml:"flags"`
		Seq       *uint32  `yaml:"seq"`
		Ack       *uint32  `yaml:"ack"`
		ClientISN uint32   `yaml:"client_isn"`
		ServerISN uint32   `yaml:"server_isn"`
		MSS       *uint16  `yaml:"mss"`      // SYN 通告 option(展开器仅在 SYN 上设)
		Checksum  *Hex     `yaml:"checksum"` // 解析但忽略
	}
	TCPSessionFields struct {
		Open  string `yaml:"open"`  // handshake(默认)| none
		Close string `yaml:"close"` // fin(默认)| rst | none
	}
	UDPFields struct {
		SPort uint16 `yaml:"sport"`
		DPort uint16 `yaml:"dport"`
	}
	ICMPFields struct {
		Type       yaml.Node `yaml:"type"`
		Code       yaml.Node `yaml:"code"`
		ID         *Hex      `yaml:"id"`
		Seq        uint16    `yaml:"seq"`
		Payload    string    `yaml:"payload"`
		PayloadHex string    `yaml:"payload_hex"`
		Quote      *Packet   `yaml:"quote"`
		QuoteFrom  string    `yaml:"quote_from"`
		Checksum   *Hex      `yaml:"checksum"` // 解析但忽略
		// 类型相关字段(RFC 792),映射到 ICMPv4 头 bytes 4-7(Id/Seq 位):
		Gateway *string `yaml:"gateway"` // 仅 redirect(type 5):网关 IPv4(bytes 4-7)
		Pointer *uint8  `yaml:"pointer"` // 仅 parameter_problem(type 12):出错字节偏移(byte 4)
		MTU     *uint16 `yaml:"mtu"`     // 仅 dest_unreachable(type 3) code 4:下一跳 MTU(bytes 6-7,RFC 1191)
	}
	// ICMPv6Fields;校验和依赖 IPv6 伪首部(由 builder 绑定,见 buildICMPv6)。
	ICMPv6Fields struct {
		Type       yaml.Node `yaml:"type"`
		Code       yaml.Node `yaml:"code"`
		ID         *Hex      `yaml:"id"`
		Seq        uint16    `yaml:"seq"`
		Payload    string    `yaml:"payload"`
		PayloadHex string    `yaml:"payload_hex"`
		Quote      *Packet   `yaml:"quote"`
		QuoteFrom  string    `yaml:"quote_from"`
		Checksum   *Hex      `yaml:"checksum"` // 解析但忽略
		// 类型相关 4 字节字段(RFC 4443 §3):仅错误报文使用,echo 不用。
		MTU     *uint32 `yaml:"mtu"`     // 仅 packet_too_big(type 2):下一跳 MTU
		Pointer *uint32 `yaml:"pointer"` // 仅 parameter_problem(type 4):出错字节偏移
	}
	PayloadFields struct {
		Payload    string `yaml:"payload"`
		PayloadHex string `yaml:"payload_hex"`
	}
	// PayloadHex 对应 `- payload_hex: "0xdeadbeef"`(值是标量,非 map)。
	PayloadHex string

	DNSFields struct {
		ID                 uint16              `yaml:"id"`
		QR                 string              `yaml:"qr"`
		Opcode             string              `yaml:"opcode"`
		RCode              string              `yaml:"rcode"`
		Authoritative      bool                `yaml:"authoritative"`
		Truncated          bool                `yaml:"truncated"`
		RecursionDesired   bool                `yaml:"recursion_desired"`
		RecursionAvailable bool                `yaml:"recursion_available"`
		AuthenticatedData  bool                `yaml:"authenticated_data"`
		CheckingDisabled   bool                `yaml:"checking_disabled"`
		Questions          []DNSQuestionFields `yaml:"questions"`
		Answers            []DNSRRFields       `yaml:"answers"`
		Authorities        []DNSRRFields       `yaml:"authorities"`
		Additionals        []DNSRRFields       `yaml:"additionals"`
	}
	DNSQuestionFields struct {
		Name  string `yaml:"name"`
		Type  string `yaml:"type"`
		Class string `yaml:"class"`
	}
	DNSRRFields struct {
		Name       string    `yaml:"name"`
		Type       string    `yaml:"type"`
		Class      string    `yaml:"class"`
		TTL        uint32    `yaml:"ttl"`
		Data       yaml.Node `yaml:"data"`
		PayloadHex string    `yaml:"payload_hex"` // 原始 RDATA 字节,用于畸形/未知 type(走手写编码路径)
	}

	HTTPReqFields struct {
		Method    string         `yaml:"method"`
		URL       string         `yaml:"url"`
		Version   string         `yaml:"version"`
		Headers   HeaderMap      `yaml:"headers"` // 保留 YAML 声明顺序、支持重复头(如多个 Set-Cookie)
		Body      string         `yaml:"body"`
		Multipart *MultipartBody `yaml:"multipart"` // MIME multipart body(RFC 2046);与 body/raw 互斥;非层,嵌在本层内
	}
	HTTPRespFields struct {
		Version   string         `yaml:"version"`
		Status    int            `yaml:"status"`
		Reason    string         `yaml:"reason"`
		Headers   HeaderMap      `yaml:"headers"` // 保留 YAML 声明顺序、支持重复头(如多个 Set-Cookie)
		Body      string         `yaml:"body"`
		Multipart *MultipartBody `yaml:"multipart"` // MIME multipart body(RFC 2046);与 body 互斥;非层,嵌在本层内
	}
	// FTPRequestFields 是一条 FTP 控制连接命令:COMMAND[ arg]\r\n。
	// command 原样输出(不强制大写),以便构造小写/非标命令等畸形用例。
	FTPRequestFields struct {
		Command string `yaml:"command"`
		Args    string `yaml:"args"`
	}
	// FTPResponseFields 是一条 FTP 控制连接响应。
	// 单行:message -> "code message\r\n"。
	// 多行(续行):lines -> "code-line1\r\n…\rcode lastline\r\n",
	// 最后一行用空格前缀,其余用连字符前缀(RFC 959 §4.1.3)。
	FTPResponseFields struct {
		Code    int      `yaml:"code"`
		Message string   `yaml:"message"`
		Lines   []string `yaml:"lines"`
	}

	// TelnetFields 是一个 TELNET 事件(IAC 命令 / subnegotiation / NVT 文本),
	// 序列化为 TCP payload 字节。多个事件在同一 TCP 段内靠层栈重复多个 telnet 层拼接
	// (SerializeLayers 顺序追加 Payload);跨段会话靠 flow 的 messages 列表。
	//
	//   - command:IAC 动词 WILL/WONT/DO/DONT/SB/GA/BRK/IP/AO/AYT/EC/EL/NOP/DM/EOR;
	//     留空表示纯 NVT 文本(此时须有 args 或 args_hex)。
	//   - option:option 码(已知名 ECHO/SGA/TTYPE/… 或十进制/0x 数字);仅协商/SB 用。
	//   - args:文本内容(SB subneg 内容或 NVT 文本),其中字面 0xFF 自动转义为 IAC IAC;
	//     NVT 文本(command 空)的裸 CR 按 RFC 854 §2 归一为 CR NUL,CR LF 行结束原样保留。
	//   - args_hex:二进制内容(SB 原始字节或 NVT 文本原始字节,如 NAWS),不转义。与 args 互斥。
	TelnetFields struct {
		Command string `yaml:"command"`
		Option  string `yaml:"option"`
		Args    string `yaml:"args"`
		ArgsHex string `yaml:"args_hex"`
	}

	// SMTPRequestFields 是一条 SMTP 信封命令。MAIL/RCPT 走结构化信封路径(from/to + params);
	// 其余 verb(EHLO/AUTH/BDAT/…)用 args 携带普通参数(verb 仍走 knownSMTPVerbs 校验)。
	// 私有/非标 verb、MAIL/RCPT 的结构性畸形(缺 <>、非标空格、FROM/TO 大小写非标、缺冒号)不走 args,
	// 而是走 payload/payload_hex 原始字节兜底。
	//
	// from 用 *string(指针)而非裸 string,以区分「未给出」与「显式空串」:
	//   - 省略 from(nil)→ 校验报错(引导用 from: "" 表达 null reverse path),避免静默退信;
	//   - from: ""(非 nil 空串)→ <>(null reverse path,退信/bounce),opt-in 显式表达;
	//   - from: "addr" → <addr>。
	// to 保持裸 string:RCPT 必须有前向路径(RFC 5321 §4.1.2 无 null 路径语义),须非空,无歧义。
	SMTPRequestFields struct {
		Verb   string    `yaml:"verb"`   // EHLO/HELO/MAIL/RCPT/DATA/QUIT/RSET/NOOP/VRFY/EXPN/HELP/AUTH/STARTTLS/BDAT/ETRN/ATRN;非标/私有 verb 走 payload/payload_hex
		From   *string   `yaml:"from"`   // 仅 MAIL(结构化):反向路径;指针区分未给出(nil,报错)与显式空串(<>,退信)
		To     string    `yaml:"to"`     // 仅 RCPT(结构化):前向路径;须非空(RCPT 不可用 null 路径)
		Params HeaderMap `yaml:"params"` // MAIL/RCPT 扩展参数:保留声明顺序、支持重复键(多 ORCPT);空值=无值 flag(如 SMTPUTF8),非空=KEY=VALUE
		Args   string    `yaml:"args"`   // 非 MAIL/RCPT verb 的普通参数(如 EHLO 的域名、AUTH 的机制+凭证、BDAT 的 chunk-size);MAIL/RCPT 禁用 args
	}

	// SMTPResponseFields 是一条 SMTP 响应。单行/多行遵循 RFC 5321 §4.2 的 Reply-line 文法
	// (每条续行带 code- 前缀,末行 code[ SP textstring])。
	SMTPResponseFields struct {
		Code    int      `yaml:"code"`    // RFC 5321 §4.2 Reply-code = %x32-35 %x30-35 %x30-39(200-559,首位 2-5);非标响应码请用 payload / payload_hex
		Message string   `yaml:"message"` // 单行: "code message\r\n"
		Lines   []string `yaml:"lines"`   // 多行续行: code-text / code final(RFC 5321 每行带 code- 前缀)
	}

	// POP3RequestFields 是一条 POP3 客户端命令(RFC 1939),序列化为 TCP payload 字节
	// "COMMAND[ args]\r\n"。字段对齐 ftp_request 的扁平 {command, args} 风格:POP3 命令
	// 无 SMTP MAIL/RCPT 那种结构化信封,统一走 command + args。
	//
	// command 原样输出(不强制大写),保留 user/retr 等小写构造能力(RFC 1939 §3 命令
	// 大小写不敏感,是合规测试点);非标/私有命令走 payload/payload_hex。
	POP3RequestFields struct {
		Command string `yaml:"command"` // RFC 1939 核心(USER/PASS/APOP/STAT/LIST/RETR/DELE/NOOP/RSET/TOP/UIDL/QUIT)+ 扩展(CAPA/STLS/AUTH);非标/私有命令走 payload/payload_hex
		Args    string `yaml:"args"`    // 命令参数(如 USER 的邮箱名、RETR 的 msg#、TOP 的 "msg# n"、APOP 的 "name digest");有/无按 pop3ArgsRule 校验
	}

	// POP3ResponseFields 是一条 POP3 服务器响应(RFC 1939)。单行 "+OK/-ERR [text]\r\n",
	// 或多行(status 行 + 正文行 + <CRLF>.<CRLF> 终止符)。
	//
	// status 原样输出(不强制大写),保留 +ok/-err 等大小写构造能力;非标状态指示符
	// (非 +OK/-ERR)走 payload/payload_hex。
	//
	// message / lines / eml 三者互斥且至少其一非空(裸 status 行走 payload/payload_hex):
	//   - message:单行 "+OK message\r\n"。
	//   - lines:多行普通行列表(LIST/UIDL 扫描列表、CAPA 能力列表),逐行 dot-stuff +
	//     追加 <CRLF>.<CRLF> 终止符(与 eml_data 同一 dot-stuff 规则)。
	//   - eml:多行 RFC 5322 邮件内容(RETR/TOP 返回的正文),复用 EMLDataFields 子结构
	//     (由 builder.serializeEMLData 处理 dot-stuff + 终止符,协议无关)。与 message/lines 互斥。
	POP3ResponseFields struct {
		Status  string         `yaml:"status"`  // +OK / -ERR(大小写不敏感,原样输出);非标状态指示符走 payload/payload_hex
		Message string         `yaml:"message"` // 单行:"+OK message\r\n";与 lines/eml 互斥
		Lines   []string       `yaml:"lines"`   // 多行普通行(LIST/UIDL/CAPA…);逐行 dot-stuff + 终止符;与 message/eml 互斥
		EML     *EMLDataFields `yaml:"eml"`     // 多行 RFC 5322 正文(RETR/TOP);复用 eml_data 子结构(dot-stuff + 终止符由其内部处理);与 message/lines 互斥
	}

	// EMLDataFields 是一封 RFC 5322 邮件内容(headers + body)，协议无关。
	// 一个 eml_data 层 = 一封完整邮件内容，序列化为 TCP payload 字节。
	//
	// 协议复用：RFC 5322 内容是 SMTP/POP3/IMAP 的共同核心。SMTP DATA（RFC 5321）
	// 与 POP3 RETR（RFC 1939）使用行框架（dot-stuffing + <CRLF>.<CRLF> 终止符），
	// IMAP FETCH（RFC 9051）使用长度前缀字面量（{n}\r\n + bytes，无 dot-stuffing/终止符）。
	// eml_data 通过 dot_stuff / dot_terminate 开关适配三种协议：SMTP/POP3 用 on（默认），
	// IMAP FETCH 由 imap_response builder 自动覆写为 off（IMAP 的 {n} 长度前缀由 builder 负责包装）。
	//
	// 两种模式（互斥，由校验保证）：
	//   - 结构化模式：headers + body（headers 必填，body 可空＝合规空体邮件），
	//     builder 自动拼装头体、dot-stuffing、终止符；
	//   - 原始模式：raw 字段直接透传整个正文字节（含/不含终止符由 dot_terminate 控制），
	//     用于构造无法用结构化字段表达的畸形正文（如无头、缺头、非法头、缺空行、非标换行）。
	//
	// headers 保留 YAML 声明顺序输出、支持重复头(如多个 Received、RFC 5322 §3.6
	// Received 链按序排列)与有序头。headers 值裸透传不转义,值含
	// \r\n + 空白可实现 RFC 5322 §2.2.3 folding(合规),值含 \r\n + 非空白为头注入(畸形)。
	// body 支持 @file(path) 注入外部文件内容(file_placeholder.go 反射遍历自动覆盖)。
	// body 行结束符:结构化模式自动把裸 \n 归一化为 \r\n(builder.normalizeCRLF,
	// 抹平 YAML `|` 块标量等常用写法带入的裸 \n);raw 模式不归一化(保留精确字节,
	// 构造非标换行畸形)。
	EMLDataFields struct {
		Headers      HeaderMap      `yaml:"headers"`       // 结构化模式：邮件头（RFC 5322），保留声明顺序、支持重复头
		Body         string         `yaml:"body"`          // 结构化模式：邮件正文体（headers 与 body 间自动插空行 \r\n）
		Multipart    *MultipartBody `yaml:"multipart"`     // 结构化模式：MIME multipart body(RFC 2046);与 body/raw 互斥;非层,嵌在本层内
		Raw          string         `yaml:"raw"`           // 原始模式：整个正文字节裸透传（不拼头体、不做 dot-stuffing）
		RawHex       string         `yaml:"raw_hex"`       // 原始模式（hex）：0x 前缀十六进制正文字节
		DotStuff     string         `yaml:"dot_stuff"`     // on（缺省）/ off：行首 . → ..；结构化模式作用于整个 content（合规 header 的 folding 续行以 WSP 起始，不受影响；构造 header 区行首 . 的畸形用 raw）
		DotTerminate string         `yaml:"dot_terminate"` // on（缺省）/ off：是否追加终止符 <CRLF>.<CRLF>
	}

	// MultipartBody 描述一个 MIME multipart 体(RFC 2046),作 HTTP 或 EML 的 body。
	// 非「层」:不能独立出现在 stack 里,而是嵌在 http_request/http_response/eml_data 内部作为子字段。
	// boundary 必须与父层 Content-Type 头里的 boundary= 参数一致(一致性告警覆盖,见 multipart_consistency.go)。
	// v1 不支持嵌套 multipart 与 preamble/epilogue(见设计文档),需要时走父层原始字节兜底
	// (eml_data 的 raw/raw_hex、http 的 payload/payload_hex)手拼。
	MultipartBody struct {
		Boundary string          `yaml:"boundary"` // 分界符;空 → 确定性默认 "----=_pMaker_0001"
		Parts    []MultipartPart `yaml:"parts"`
	}

	// MultipartPart 是 multipart 体的一个 part(RFC 2046)。
	// part 头复用 HeaderMap(保序、可重复键,如多个 Content-Disposition 参数)。
	MultipartPart struct {
		Headers  HeaderMap `yaml:"headers"`  // part 头(Content-Disposition/Content-Type/Content-Transfer-Encoding…),保序、可重复
		Body     string    `yaml:"body"`     // part 体;支持 @file 注入(文本或二进制附件);与 body_hex 互斥
		BodyHex  string    `yaml:"body_hex"` // part 体(hex,二进制附件);与 body 互斥;不可用 @file(hex 字段注入原始字节会破坏 hex 语义,二进制附件请用 body + @file)
		Encoding string    `yaml:"encoding"` // none(缺省)/base64/quoted-printable:对 body/body_hex 做传输编码
	}
)
