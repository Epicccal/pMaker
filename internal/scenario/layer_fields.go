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
	// ICMPv6Fields 镜像 ICMPFields;校验和依赖 IPv6 伪首部(见 builder)。
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
		PayloadHex string    `yaml:"payload_hex"` // 预留:畸形/未知 RDATA 后续实现
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
	// 对齐 ftp_request 的 {command, args} 扁平风格。
	//
	//   - command:IAC 动词 WILL/WONT/DO/DONT/SB/GA/BRK/IP/AO/AYT/EC/EL/NOP/DM/EOR;
	//     留空表示纯 NVT 可见文本(此时须有 args)。
	//   - option:option 码(已知名 ECHO/SGA/TTYPE/… 或十进制/0x 数字);仅协商/SB 用。
	//   - args:文本内容(SB subneg 内容或 NVT 文本),其中字面 0xFF 自动转义为 IAC IAC。
	//   - args_hex:二进制内容(SB 原始字节,如 NAWS),不转义。与 args 互斥。
	TelnetFields struct {
		Command string `yaml:"command"`
		Option  string `yaml:"option"`
		Args    string `yaml:"args"`
		ArgsHex string `yaml:"args_hex"`
	}
)
