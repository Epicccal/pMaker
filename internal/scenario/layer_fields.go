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
		Method  string            `yaml:"method"`
		URL     string            `yaml:"url"`
		Version string            `yaml:"version"`
		Headers map[string]string `yaml:"headers"`
		Body    string            `yaml:"body"`
	}
	HTTPRespFields struct {
		Version string            `yaml:"version"`
		Status  int               `yaml:"status"`
		Reason  string            `yaml:"reason"`
		Headers map[string]string `yaml:"headers"`
		Body    string            `yaml:"body"`
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
		Verb   string            `yaml:"verb"`   // EHLO/HELO/MAIL/RCPT/DATA/QUIT/RSET/NOOP/VRFY/EXPN/HELP/AUTH/STARTTLS/BDAT/ETRN/ATRN;非标/私有 verb 走 payload/payload_hex
		From   *string           `yaml:"from"`   // 仅 MAIL(结构化):反向路径;指针区分未给出(nil,报错)与显式空串(<>,退信)
		To     string            `yaml:"to"`     // 仅 RCPT(结构化):前向路径;须非空(RCPT 不可用 null 路径)
		Params map[string]string `yaml:"params"` // MAIL/RCPT 扩展参数:键=参数名(SIZE/BODY/AUTH/NOTIFY/SMTPUTF8/ORCPT/RET/ENVID…),值=参数值(空值=无值 flag,如 SMTPUTF8)
		Args   string            `yaml:"args"`   // 非 MAIL/RCPT verb 的普通参数(如 EHLO 的域名、AUTH 的机制+凭证、BDAT 的 chunk-size);MAIL/RCPT 禁用 args
	}

	// SMTPResponseFields 是一条 SMTP 响应。单行/多行遵循 RFC 5321 §4.2 的 Reply-line 文法
	// (每条续行带 code- 前缀,末行 code[ SP textstring])。
	SMTPResponseFields struct {
		Code    int      `yaml:"code"`    // RFC 5321 §4.2 Reply-code = %x32-35 %x30-35 %x30-39(200-559,首位 2-5);非标响应码请用 payload / payload_hex
		Message string   `yaml:"message"` // 单行: "code message\r\n"
		Lines   []string `yaml:"lines"`   // 多行续行: code-text / code final(RFC 5321 每行带 code- 前缀)
	}
)
