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
		VID uint16 `yaml:"vid"`
		// 方向化 VID(仅 flow.stack 有效,与 vid 互斥):flow 展开器按消息方向逐包取值。
		// src_vid = src→dst(TCP SYN 发起方发出的包)方向的 VID,dst_vid = dst→src 方向。
		// 单边缺省(nil)= 该方向整层摘除(此方向的包里没有这一层标签),
		// 由此表达「上行带标签 / 下行不带」「上行双层 / 下行单层」。
		SrcVID *uint16 `yaml:"src_vid"`
		DstVID *uint16 `yaml:"dst_vid"`
		Pri    *uint8  `yaml:"pri"`  // PCP 优先级(3 位,0-7;缺省 0);与方向 VID 共存时两向共用
		DEI    *bool   `yaml:"dei"`  // Drop Eligible Indicator(1 位;缺省 false);两向共用
		Type   *Hex    `yaml:"type"` // 显式覆盖本层标签后的 TPID/EtherType(制造断链;缺省自动推导);两向共用
	}
	IPv4Fields struct {
		Src      string  `yaml:"src"`
		Dst      string  `yaml:"dst"`
		TTL      *uint8  `yaml:"ttl"`
		Protocol *string `yaml:"protocol"` // 覆盖:tcp/udp/gre/ipv4
		// 畸形覆盖。checksum/length 两态:nil=自动计算,非 nil=原样落值(关闭自动计算/修正)。
		Checksum *Hex `yaml:"checksum"`
		Length   *Hex `yaml:"total_length"`  // 总长度(16 位,上限 0xFFFF);写即覆盖原样上 wire,不写=自动计算
		IHL      *Hex `yaml:"header_length"` // 头部长度(IHL,4 位,可写 0-15,上限 0xF);写即覆盖,不写=自动计算。5-15 为规范范围,0-4 合法畸形
		// MTU 是自动分片开关:int(>0) = 整个 IP 数据报(头+载荷)超过该值时自动切片。
		// 不写(0)= 永不分片。分片 ID 由 builder 的确定性计数器分配,不开放 YAML 字段;
		// 与 total_length/header_length/checksum 互斥(各片长度与校验和须逐片重算,见校验)。
		MTU int `yaml:"mtu"`
	}
	IPv6Fields struct {
		Src           string  `yaml:"src"`
		Dst           string  `yaml:"dst"`
		HopLimit      *uint8  `yaml:"hop_limit"` // 跳数限制(类比 IPv4 ttl),缺省 64
		TrafficClass  *uint8  `yaml:"traffic_class"`
		FlowLabel     *uint32 `yaml:"flow_label"`
		NextHeader    *string `yaml:"next_header"`    // 覆盖:tcp/udp/icmpv6/ipv4/ipv6(制造断链)
		PayloadLength *Hex    `yaml:"payload_length"` // 载荷长度(16 位,上限 0xFFFF,不含 40B 头);写即覆盖,不写=自动计算
		// MTU 是自动分片开关,语义与 ipv4.mtu 一致:超过时在主头后插入 Fragment 扩展头
		// (RFC 8200 §4.5,由 builder 构造,不作为独立 YAML 层)。与 payload_length 互斥。
		MTU int `yaml:"mtu"`
	}
	GREFields   struct{}
	VXLANFields struct {
		VNI         uint32 `yaml:"vni"`           // 24 位 VNI(0 合法,边界用;上限 0xFFFFFF 校验拦截)
		ValidIDFlag *bool  `yaml:"valid_id_flag"` // 'I' 位(RFC 7348);nil=缺省 true(规范头),false=非法头畸形
	}
	TCPFields struct {
		SPort      uint16   `yaml:"sport"`
		DPort      uint16   `yaml:"dport"`
		Flags      []string `yaml:"flags"`
		Seq        *uint32  `yaml:"seq"`
		Ack        *uint32  `yaml:"ack"`
		ClientISN  uint32   `yaml:"client_isn"`
		ServerISN  uint32   `yaml:"server_isn"`
		MSS        *uint16  `yaml:"mss"`           // SYN 通告 option(展开器仅在 SYN 上设)
		Checksum   *Hex     `yaml:"checksum"`      // 两态:nil=自动计算(伪首部照常绑定),非 nil=原样落值
		DataOffset *Hex     `yaml:"header_length"` // 数据偏移(4 位,可写 0-15,上限 0xF,以 4 字节为单位);写即覆盖,不写=自动计算。5-15 为规范范围,0-4 合法畸形
	}
	TCPSessionFields struct {
		Open  string `yaml:"open"`  // handshake(默认)| none
		Close string `yaml:"close"` // fin(默认)| rst | none
	}
	// UDPSessionFields 是 flow 的 UDP 会话标记层。UDP 无连接,故无 open/close。
	// 无需承载任何字段, 字段留空是刻意的 —— 见 _why_udp_session.md。
	UDPSessionFields struct{}
	UDPFields        struct {
		SPort    uint16 `yaml:"sport"`
		DPort    uint16 `yaml:"dport"`
		Checksum *Hex   `yaml:"checksum"`     // 两态:nil=自动计算(伪首部照常绑定),非 nil=原样落值
		Length   *Hex   `yaml:"total_length"` // udp 总长度(16 位,上限 0xFFFF,头 8 + payload);写即覆盖,不写=自动计算
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
		Checksum   *Hex      `yaml:"checksum"` // 两态:nil=自动计算(伪首部照常绑定),非 nil=原样落值
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
		Checksum   *Hex      `yaml:"checksum"` // 两态:nil=自动计算(伪首部照常绑定),非 nil=原样落值
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
		Method            string          `yaml:"method"`
		URL               string          `yaml:"url"`
		Version           string          `yaml:"version"`
		Headers           HeaderMap       `yaml:"headers"` // 保留 YAML 声明顺序、支持重复头(如多个 Set-Cookie)
		Body              string          `yaml:"body"`
		Multipart         *MultipartBody  `yaml:"multipart"`           // MIME multipart body(RFC 2046);与 body/raw 互斥;非层,嵌在本层内
		AutoContentLength bool            `yaml:"auto_content_length"` // true=回填/覆盖 Content-Length 值(缺则末尾追加);false(缺省)=不动 Header
		ContentEncoding   CodingList      `yaml:"content_encoding"`    // 表示层编码,按序应用;标量或序列;元素 ∈ gzip/deflate/deflate_raw/br/compress
		TransferEncoding  CodingList      `yaml:"transfer_encoding"`   // 传输层编码/成帧,按序应用;标量或序列;元素 ∈ chunked/gzip/deflate/deflate_raw/compress
		Chunked           *ChunkedOptions `yaml:"chunked"`             // chunked 专属参数子结构;缺省 nil=整段一块;仅 transfer_encoding 含 chunked 时有效
	}
	HTTPRespFields struct {
		Version           string          `yaml:"version"`
		Status            int             `yaml:"status"`
		Reason            string          `yaml:"reason"`
		Headers           HeaderMap       `yaml:"headers"` // 保留 YAML 声明顺序、支持重复头(如多个 Set-Cookie)
		Body              string          `yaml:"body"`
		Multipart         *MultipartBody  `yaml:"multipart"`           // MIME multipart body(RFC 2046);与 body 互斥;非层,嵌在本层内
		AutoContentLength bool            `yaml:"auto_content_length"` // true=回填/覆盖 Content-Length 值(缺则末尾追加);false(缺省)=不动 Header
		ContentEncoding   CodingList      `yaml:"content_encoding"`    // 表示层编码,按序应用;标量或序列;元素 ∈ gzip/deflate/deflate_raw/br/compress
		TransferEncoding  CodingList      `yaml:"transfer_encoding"`   // 传输层编码/成帧,按序应用;标量或序列;元素 ∈ chunked/gzip/deflate/deflate_raw/compress
		Chunked           *ChunkedOptions `yaml:"chunked"`             // chunked 专属参数子结构;缺省 nil=整段一块;仅 transfer_encoding 含 chunked 时有效
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
	// 其余 verb(EHLO/AUTH/BDAT/…)用 args 携带普通参数(verb 仍走 smtpVerbs 校验)。
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
		Args    string `yaml:"args"`    // 命令参数(如 USER 的邮箱名、RETR 的 msg#、TOP 的 "msg# n"、APOP 的 "name digest");有/无按 pop3Commands 策略校验
	}

	// POP3ResponseFields 是一条 POP3 服务器响应(RFC 1939)。单行 "+OK/-ERR [text]\r\n",
	// 或多行(status 行 + 正文行 + <CRLF>.<CRLF> 终止符);SASL 续行挑战为 "+ [base64]\r\n"
	// (RFC 1734/4954,单字符 + 而非 +OK)。
	//
	// status 原样输出(不强制大写),保留 +ok/-err 等大小写构造能力;非标状态指示符
	// (非 +OK/-ERR/+)走 payload/payload_hex。
	//
	// message 是状态行附带文本,可与多行正文(lines/eml)组合,也可单独(单行响应):
	//   - message 单独非空(无 lines/eml):单行 "+OK message\r\n"(SASL 续行则为
	//     "+ <base64>\r\n",message 承载 base64 挑战)。
	//   - message + lines/eml:多行响应首行带说明文本(RFC 1939 §3 合法形态,如 LIST 的
	//     "+OK 2 messages (320 octets)"、CAPA 的 "+OK Capability list follows"),
	//     形如 "+OK text\r\n<正文>\r\n.\r\n"。
	//   - message 为空 + lines/eml:裸 status 行 + 多行正文("+OK\r\n<正文>\r\n.\r\n")。
	//   - lines/eml 二者互斥(多行正文二选一);message 与二者均可组合。
	//   - message/lines/eml 至少其一非空(裸 status 行走 payload/payload_hex)。
	//
	// lines:多行普通行列表(LIST/UIDL 扫描列表、CAPA 能力列表),逐行 dot-stuff +
	//   追加 <CRLF>.<CRLF> 终止符(与 eml_data 同一 dot-stuff 规则)。
	// eml:多行 RFC 5322 邮件内容(RETR/TOP 返回的正文),复用 EMLDataFields 子结构
	//   (builder.SerializeEMLData 只产纯 RFC 5322 内容、不含成帧;dot-stuff + 终止符
	//   由 POP3 接入层 serializePOP3Resp 在其返回后强制追加,与 lines 分支同一职责)。
	//   与 lines 互斥。
	POP3ResponseFields struct {
		Status  string         `yaml:"status"`  // +OK / -ERR / +(大小写不敏感,原样输出);+ 为 RFC 1734/4954 SASL 续行挑战;非标状态指示符走 payload/payload_hex
		Message string         `yaml:"message"` // 状态行附带文本:单独非空=单行响应(SASL 续行则承载 base64 挑战);与 lines/eml 组合=多行首行带说明文本(RFC 1939 §3)
		Lines   []string       `yaml:"lines"`   // 多行普通行(LIST/UIDL/CAPA…);逐行 dot-stuff + 终止符;与 eml 互斥
		EML     *EMLDataFields `yaml:"eml"`     // 多行 RFC 5322 正文(RETR/TOP);复用 eml_data 子结构(其只产纯内容,dot-stuff + 终止符由 POP3 接入层追加);与 lines 互斥
	}

	// IMAPRequestFields 是一条 IMAP 客户端输入(RFC 9051)。三形式互斥:
	//   A. 命令行:tag + command [+ args] [+ literal],序列化为 "tag SP command [SP args] [SP literal]\r\n"
	//   B. 裸行:  line(DONE / AUTHENTICATE 续行 base64 / 取消 literal 的 "*"),序列化为 "line\r\n"
	//   C. 八位组:literal.emit = data(同步 literal 的第二个 TCP 消息),序列化为 <八位组> + "\r\n"
	//
	// IMAP 是「行 + 长度前缀混合定界」(RFC 9051 §2.2):literal 嵌在命令/响应中间,前后都有
	// 文本。client→server 同步 literal({n})须等待服务器 + 续行才能发数据,故一条 APPEND 在线上
	// 是三条消息(① 命令行+{n}\r\n ② 服务器 + ③ 八位组+CRLF),用 emit 三态表达(决策 4)。
	//
	// tag 原样输出(不强制大写),保留大小写构造能力(RFC 9051 §2.2 tag 大小写敏感);
	// tag 字符集:1*<any ASTRING-CHAR except "+">,+ 被显式排除(与 continuation 的 + 前缀歧义),
	// ] 合法(resp-specials)。非标/私有命令、非末位 literal 等结构化路径表达不了的形态走
	// payload/payload_hex(与全项目「非标值走原始字节兜底」一致)。
	IMAPRequestFields struct {
		Tag     string       `yaml:"tag"`     // 1*<any ASTRING-CHAR except "+">;形式 A 必填;非空、不含 + 与 atom-specials
		Command string       `yaml:"command"` // 已知命令表(大小写不敏感,原样输出);形式 A 必填;非标/私有命令走 payload/payload_hex
		Args    string       `yaml:"args"`    // 命令参数裸透传,不解析;有/无按命令策略校验;禁含裸 \r \n
		Line    string       `yaml:"line"`    // 形式 B:裸行文本(DONE / SASL base64 续行 / 取消 literal 的 *);与 tag/command/args 互斥;禁含裸 \r \n
		Literal *IMAPLiteral `yaml:"literal"` // 长度前缀八位组(可附在命令行末尾,或 emit=data 作为形式 C 独立消息)
	}

	// IMAPResponseFields 是一条 IMAP 服务器响应(RFC 9051)。tag 三态定型:具体 tag = tagged;
	// "*" = untagged;"+" = continuation。首 token ∈ {tag, *, +} 三选一且互斥。
	//
	// 字段分两组,由文法判别、互斥(决策 7):
	//   状态组 status+code+text —— resp-cond-state(OK/NO/BAD)/ resp-cond-bye(BYE)/ resp-cond-auth(PREAUTH)
	//   数据组 data+literal+tail —— mailbox-data / message-data / capability-data / enable-data
	// 未标记状态响应(如 "* OK [UIDVALIDITY 3857529045] UIDs valid")走状态组,
	// 不得写进 data;非标间距等成帧畸形走 payload / payload_hex。
	//
	// data 的首 token 不得为 OK/NO/BAD/PREAUTH/BYE(那是状态形式,后跟 SP 或行尾,大小写不敏感)——
	// 这条才真正封死「状态响应误写进 data」的歧义。data/literal/tail 须依附数据组;
	// code/text 须依附状态组。tag "+" 时仅 text 允许(continue-req = "+" SP (resp-text / base64) CRLF)。
	IMAPResponseFields struct {
		Tag     string       `yaml:"tag"`     // tag / "*" / "+";空报错
		Status  string       `yaml:"status"`  // OK/NO/BAD/PREAUTH/BYE(大小写不敏感,原样输出);tagged(具体 tag)仅 OK/NO/BAD;依附状态组
		Code    string       `yaml:"code"`    // resp-text-code 方括号内内容,不做白名单(atom 兜底,开放扩展槽);禁含 ] 与裸 \r \n;依附状态组
		Text    string       `yaml:"text"`    // resp-text 的 text 部分;tag "+" 时唯一允许的字段;禁含裸 \r \n;依附状态组
		Data    string       `yaml:"data"`    // 数据形式响应体(literal 之前的文本);仅 tag "*";首 token 不得为 OK/NO/BAD/PREAUTH/BYE;禁含裸 \r \n
		Literal *IMAPLiteral `yaml:"literal"` // 嵌在 data 之后的长度前缀内容;须依附 data(非空)
		Tail    string       `yaml:"tail"`    // literal 之后的文本(如 msg-att 的收尾 ")");须依附 data(非空);禁含裸 \r \n
	}

	// IMAPLiteral 是一段长度前缀八位组(RFC 9051 §4.3)。IMAP 的核心定界机制:
	// "{" number64 ["+"] "}" CRLF *CHAR8(同步 {n} / 非同步 {n+})或
	// "~{" number64 "}" CRLF *OCTET(literal8 BINARY,仅 server→client)。
	//
	// 八位组内容三选一:eml(复用 eml_data 子结构,取纯 RFC 5322 内容,IMAP 加 {n} 前缀,
	// 不做 dot-stuffing/终止符)/ data(字面八位组)/ data_hex(十六进制,配 binary: true)。
	//
	// octets 两态覆盖(nil = 自动算实际字节数;非 nil = 原样落值,关闭自动计算),对齐
	// checksum / length 先例:声明 octets: 9999 而实际 342 字节是构造「计数撒谎」解析器
	// 攻击用例的唯一手段,必须原样落值。计数不一致产软告警(非硬错)。
	//
	// sync 缺省 true = {n};false = {n+} 非同步(仅 client→server,server MUST NOT 发)。
	// binary true = literal8 "~{n}"(仅 server→client BINARY FETCH);literal8 文法上无 {n+}
	// 非同步形式,故 binary: true 且 sync: false → 硬错(决策 8)。
	// emit: full(缺省)= {n}\r\n+数据;prefix = 仅 {n}\r\n(同步 literal 第①段);
	// data = 仅数据(同步 literal 第③段)。
	IMAPLiteral struct {
		EML     *EMLDataFields `yaml:"eml"`      // RFC 5322 内容,复用 eml_data 子结构(取纯内容,IMAP 加 {n} 前缀,无 dot-stuffing/终止符)
		Data    string         `yaml:"data"`     // 字面八位组
		DataHex string         `yaml:"data_hex"` // 十六进制八位组(二进制,配 binary: true)
		Octets  *int           `yaml:"octets"`   // 两态:nil=自动算;非 nil=原样落值(关闭自动计算)
		Sync    *bool          `yaml:"sync"`     // 缺省 true={n};false={n+} 非同步,仅 client→server
		Binary  bool           `yaml:"binary"`   // true=literal8 "~{n}"(RFC 9051 §4.3.1,仅 server→client)
		Emit    string         `yaml:"emit"`     // full(缺省)/prefix/data
	}

	// EMLDataFields 是一封 RFC 5322 邮件内容(headers + body)，协议无关的**内容层**。
	// 一个 eml_data 层 = 一封完整邮件内容，序列化为 TCP payload 字节（纯 RFC 5322 内容，
	// 不含成帧）。
	//
	// 协议复用：RFC 5322 内容是 SMTP/POP3/IMAP 的共同核心。成帧（framing）是传输协议的
	// 职责，由接入层强制，不在内容层暴露开关：
	//   - SMTP DATA（RFC 5321 §4.5.2）/ POP3 RETR（RFC 1939 §3）：接入层（builder 的
	//     eml_data standalone 分支 / pop3_response 的 eml 分支）强制 dot-stuffing +
	//     追加 <CRLF>.<CRLF> 终止符，无 opt-out；缺 dot-stuffing/缺终止符等畸形走
	//     payload/payload_hex 原始字节兜底。
	//   - IMAP FETCH（RFC 9051）：未来由 imap_response builder 用长度前缀 {n}\r\n 包装
	//     纯内容字节（无需 dot-stuffing/终止符），同样不操作内容层字段。
	//
	// 两种模式（互斥，由校验保证）：
	//   - 结构化模式：headers + body（headers 必填，body 可空＝合规空体邮件），
	//     builder 自动拼装头体（+ 空行）；成帧由接入层追加。
	//   - 原始模式：raw 字段直接透传整个内容字节（不含成帧），用于构造无法用结构化
	//     字段表达的畸形正文（如无头、缺头、非法头、缺空行、非标换行）；成帧仍由接入层追加。
	//
	// headers 保留 YAML 声明顺序输出、支持重复头(如多个 Received、RFC 5322 §3.6
	// Received 链按序排列)与有序头。headers 值裸透传不转义,值含
	// \r\n + 空白可实现 RFC 5322 §2.2.3 folding(合规),值含 \r\n + 非空白为头注入(畸形)。
	// body 支持 @file(path) 注入外部文件内容(file_placeholder.go 反射遍历自动覆盖)。
	// body 行结束符:结构化模式自动把裸 \n 归一化为 \r\n(util/crlf.NormalizeCRLF,
	// builder 与 scenario 的 IMAP literal 一致性告警共用同一份原语);raw 模式不归一化(保留精确字节,
	// 构造非标换行畸形)。
	EMLDataFields struct {
		Headers   HeaderMap      `yaml:"headers"`   // 结构化模式：邮件头（RFC 5322），保留声明顺序、支持重复头
		Body      string         `yaml:"body"`      // 结构化模式：邮件正文体（headers 与 body 间自动插空行 \r\n）
		Multipart *MultipartBody `yaml:"multipart"` // 结构化模式：MIME multipart body(RFC 2046);与 body/raw 互斥;非层,嵌在本层内
		Raw       string         `yaml:"raw"`       // 原始模式：整个内容字节裸透传（不拼头体、不含成帧；成帧由接入层追加）
		RawHex    string         `yaml:"raw_hex"`   // 原始模式（hex）：0x 前缀十六进制内容字节
	}

	// ChunkedOptions 是 chunked 成帧的专属参数,仅在 transfer_encoding 含 chunked 时有效。
	ChunkedOptions struct {
		Size int `yaml:"size"` // 切块大小;0/缺省=整段一块;>0=按指定大小切分;<0=硬错
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
