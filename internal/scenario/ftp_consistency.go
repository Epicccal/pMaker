package scenario

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// 本文件实现 FTP 控制通道 ↔ 数据通道的端口/IP 一致性告警(非硬错)。
//
// 支持的协商形态(RFC 959 + RFC 2428):
//   - PASV(227):响应文本六元组 (h1,h2,h3,h4,p1,h2) 声明数据连接的 IPv4:端口。
//   - PORT:请求 args 六元组,声明数据连接的 IPv4:端口。
//   - EPSV(229):响应文本 (|||port|),仅声明端口(IPv4/IPv6 通用);地址隐式为
//     控制连接的对端(即服务器侧,与 PASV 语义一致)。
//   - EPRT:请求 args |netproto|addr|port|,netproto=1(IPv4)/2(IPv6);显式声明
//     数据连接地址:端口(与 PORT 语义一致,但支持 IPv6)。
//
// 工具不强制两者联动,一旦用户改了一处忘了另一处,产出的 pcap 就是"控制连接声明
// 50000、实际数据连接去 49999"的不自洽场景——这会让下游解析端报"端口协商不一致"误报,
// 而用户无从分辨是配置错还是有意构造。本检查在校验阶段把这类不一致作为告警产出
// (warn 而非 error,因为畸形用例可能故意构造不一致以构造异常场景)。
//
// 协商端点语义:各协商 (ip, port) 始终是"被连接方"地址——
//   - PASV(227)/EPSV(229):服务器告知客户端"连我 ip:port",数据流 src=客户端、dst=服务器;
//     229 不含 IP,地址隐式为控制连接对端(服务器侧=控制流 dst IP)。
//   - PORT/EPRT:客户端告知服务器"连我 ip:port",主动模式 stack 反转使客户端成为数据流 dst。
// 故这些模式下协商端点都等于数据流的 dst IPv4 : dport,统一按此比对。
//
// 只扫描"控制通道候选"flow(sport/dport==21 或含 ftp_request/ftp_response 层)的消息,
// 避免误扫数据流里恰好含 "227"/"PORT"/"229"/"EPRT" 字样的文件内容。

// ftpPortTupleRegex 匹配带括号的六元组,用于 227 响应文本
// (如 "Entering Passive Mode (10,0,0,21,195,80).")。容忍分量间空白。
var ftpPortTupleRegex = regexp.MustCompile(`\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)`)

// portArgsRegex 匹配裸六元组(无括号、整串),用于 ftp_request PORT 的 args 字段
// (如 "10,0,0,10,192,5")。
var portArgsRegex = regexp.MustCompile(`^\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*$`)

// epsvTupleRegex 匹配 EPSV(229) 响应文本里的 (|||port|)(RFC 2428)。
// 三道竖线分隔后是扩展分隔符(默认 '|'),其内是端口。容忍分隔符为任意非空白字符。
// 仅提取端口:EPSV 不携带地址(IPv4/IPv6 通用,地址隐式为控制连接对端)。
var epsvTupleRegex = regexp.MustCompile(`\(\|\|\|(\d{1,5})\|\)`)

// eprtArgsRegex 匹配 EPRT 请求 args:|netproto|addr|port|(RFC 2428)。
// netproto=1(IPv4)/2(IPv6);addr 为对应地址字面量;port 为十进制端口。
// 分隔符固定取竖线(RFC 2428 允许任意可打印字符做分隔符,但实现界普遍用 '|';
// 非竖线分隔符属非标形态,走 payload/payload_hex 通道)。addr 段不含竖线
// (IPv6 文本无 '|'),故 [^|]+ 可正确容纳 IPv6 地址。
var eprtArgsRegex = regexp.MustCompile(`^\s*\|(\d+)\|([^|]+)\|(\d+)\|\s*$`)

// ftpNegotiation 是一条从 227/PORT/229/EPRT 文本解析出的数据连接协商端点。
type ftpNegotiation struct {
	flowName string // 所在控制流名(空名则用 "#<下标>"),用于告警定位
	msgIdx   int    // 所在消息在 flow 内的序号,用于告警定位
	kind     string // "227" | "PORT" | "229" | "EPRT"
	ip       string // 协商地址(227/PORT/EPRT 时填解析出的地址;229/EPSV 时为空,地址隐式为控制连接对端)
	port     uint16 // 协商端口(227/PORT:p1*256+p2;229/EPRT:直接十进制)
}

// flowEndpoint 是一条 flow 用于匹配的端点摘要:最近的 IPv4/IPv6 src/dst 与 TCP/UDP dport,
// 以及是否为控制通道候选。srcIP/dstIP 用于 FTP 协商地址 ↔ 控制连接角色校验。
type flowEndpoint struct {
	srcIP  string
	dstIP  string
	dport  uint16
	sport  uint16
	isCtrl bool
}

// CheckFTPDataPortConsistency 扫描 FTP 控制通道的 PASV 227 / PORT / EPSV 229 / EPRT 协商,
// 解析出协商的 IP:端口,再与场景中各 flow 的 dst IP : dport 比对。对解析失败、或协商端点
// 与数据流端点不一致的情况,产出告警(非硬错:畸形用例可能故意构造不一致以构造异常场景)。
// 返回零到多条告警,每条带 flow/message 定位。
func CheckFTPDataPortConsistency(s *Scenario) []string {
	if s == nil || len(s.Flows) == 0 {
		return nil
	}

	eps := make([]flowEndpoint, len(s.Flows))
	for i, f := range s.Flows {
		ep := flowEndpoint{}
		for _, l := range f.Stack {
			switch v := l.Fields.(type) {
			case *IPv4Fields:
				ep.srcIP = normalizeFTPAddr(v.Src)
				ep.dstIP = normalizeFTPAddr(v.Dst)
			case *IPv6Fields:
				ep.srcIP = normalizeFTPAddr(v.Src)
				ep.dstIP = normalizeFTPAddr(v.Dst)
			case *TCPFields:
				ep.dport = v.DPort
				ep.sport = v.SPort
				if v.DPort == 21 || v.SPort == 21 {
					ep.isCtrl = true
				}
			case *UDPFields:
				ep.dport = v.DPort
				ep.sport = v.SPort
				if v.DPort == 21 || v.SPort == 21 {
					ep.isCtrl = true
				}
			case *FTPRequestFields, *FTPResponseFields:
				ep.isCtrl = true
			}
		}
		eps[i] = ep
	}

	var warnings []string
	for i, f := range s.Flows {
		if !eps[i].isCtrl {
			continue
		}
		for j, m := range f.Messages {
			negotiations, parseWarns := extractFTPNegotiations(flowLabel(f.Name, i), j, m)
			warnings = append(warnings, parseWarns...)
			for _, n := range negotiations {
				warnings = append(warnings, matchNegotiation(n, s.Flows, eps, i)...)
				// 协商地址 ↔ 控制连接角色校验:227/PORT 协商的 IP 必须是控制连接的一方端点,
				// 否则声明的是与本次会话无关的地址(常见笔误或配置错),产出告警。
				warnings = append(warnings, checkNegotiationRole(n, eps[i])...)
			}
		}
	}
	return warnings
}

// extractFTPNegotiations 从单条消息提取 227/PORT 协商端点;解析失败时产出告警。
// 仅识别明确为 227/PORT 的内容(结构化 ftp_response(227)/ftp_request(PORT),或
// 原始 payload/payload_hex 文本首 token 为 "227"/"PORT"/"229"/"EPRT"),避免误判其它响应码或命令。
func extractFTPNegotiations(flowName string, msgIdx int, m Message) (negotiations []ftpNegotiation, parseWarnings []string) {
	if len(m.Stack) == 0 {
		return
	}
	// add6 解析 227/PORT 的六元组(带 IPv4 地址):成功则记端点,失败则记告警。
	add6 := func(kind, text string) {
		ip, port, ok := parseFTPPortTuple(text)
		if ok {
			negotiations = append(negotiations, ftpNegotiation{flowName, msgIdx, kind, ip, port})
			return
		}
		parseWarnings = append(parseWarnings, fmt.Sprintf(
			"flow %q 的 messages[%d] 的 %s 协商文本 %q 未解析出 IPv4:端口六元组,无法校验数据端口一致性",
			flowName, msgIdx, kind, text))
	}
	// addEpsv 解析 229(EPSV)的 (|||port|):仅端口,IP 留空(隐式为控制连接对端)。
	addEpsv := func(text string) {
		port, ok := parseEPSVTuple(text)
		if ok {
			negotiations = append(negotiations, ftpNegotiation{flowName, msgIdx, "229", "", port})
			return
		}
		parseWarnings = append(parseWarnings, fmt.Sprintf(
			"flow %q 的 messages[%d] 的 229(EPSV)协商文本 %q 未解析出 (|||port|) 端口,无法校验数据端口一致性",
			flowName, msgIdx, text))
	}
	// addEprt 解析 EPRT 的 |netproto|addr|port|:地址按 netproto 校验合法(IPv4/IPv6)。
	addEprt := func(text string) {
		ip, port, ok := parseEPRTArgs(text)
		if ok {
			negotiations = append(negotiations, ftpNegotiation{flowName, msgIdx, "EPRT", ip, port})
			return
		}
		parseWarnings = append(parseWarnings, fmt.Sprintf(
			"flow %q 的 messages[%d] 的 EPRT 协商文本 %q 未解析出 |netproto|addr|port|,无法校验数据端口一致性",
			flowName, msgIdx, text))
	}

	// message.stack 可含多个 payload 生产层(按栈顺序拼接),须逐层检查,
	// 否则把 227/PORT/229/EPRT 放在非首层时协商端点会被漏提取,致一致性校验假阴性。
	for _, l := range m.Stack {
		switch f := l.Fields.(type) {
		case *FTPResponseFields:
			switch f.Code {
			case 227:
				// 227 文本可能在 message 或 lines(多行续行)里;合并扫描,以括号六元组为准。
				var b strings.Builder
				b.WriteString(f.Message)
				for _, ln := range f.Lines {
					if ln != "" {
						b.WriteByte(' ')
						b.WriteString(ln)
					}
				}
				add6("227", b.String())
			case 229:
				// 229(EPSV)文本同 227 可能在 message 或 lines 里;合并扫描。
				var b strings.Builder
				b.WriteString(f.Message)
				for _, ln := range f.Lines {
					if ln != "" {
						b.WriteByte(' ')
						b.WriteString(ln)
					}
				}
				addEpsv(b.String())
			}
		case *FTPRequestFields:
			switch strings.ToUpper(f.Command) {
			case "PORT":
				add6("PORT", f.Args)
			case "EPRT":
				addEprt(f.Args)
			}
		case *PayloadFields:
			// 原始 payload 文本:仅在首 token 为协商命令/响应码时尝试,避免误扫文件内容。
			if kind, ok := ftpNegotiationKind(f.Payload); ok {
				switch kind {
				case "227", "PORT":
					add6(kind, f.Payload)
				case "229":
					addEpsv(f.Payload)
				case "EPRT":
					addEprt(f.Payload)
				}
			}
		case PayloadHex:
			// payload_hex 是原始字节;控制通道候选才扫到这里,解码后按文本同法判断。
			raw, err := ParsePayloadHex(string(f))
			if err != nil {
				continue
			}
			text := string(raw)
			if kind, ok := ftpNegotiationKind(text); ok {
				switch kind {
				case "227", "PORT":
					add6(kind, text)
				case "229":
					addEpsv(text)
				case "EPRT":
					addEprt(text)
				}
			}
		}
	}
	return
}

// checkNegotiationRole 校验 227/PORT/EPRT 协商的 IP 是否为控制连接的一方端点。
//
// RFC 959 / RFC 2428 语义:
//   - PASV(227):服务器告知"连我 ip:port",故协商 IP 必须是控制连接的服务器侧
//     (dport=21 一方的 IPv4/IPv6,即控制流 dst IP)。
//   - EPSV(229):不含地址,地址隐式为控制连接对端(服务器侧=控制流 dst IP),无需比对。
//   - PORT:客户端告知"连我 ip:port",故协商 IP 必须是控制连接的客户端侧
//     (sport=21 一方的 IPv4/IPv6,即控制流 src IP)。
//   - EPRT:同 PORT,客户端告知"连我 ip:port",协商 IP 必须是控制流 src IP(IPv4/IPv6)。
//
// 协商 IP 与控制连接对应角色不一致时,声明的是与本次会话无关的地址(常见笔误或配置错),
// 产出告警。畸形用例可能故意构造不一致以构造异常场景,故只告警不阻断。
// 控制流缺端点信息时跳过(无法判定)。
func checkNegotiationRole(n ftpNegotiation, ctrl flowEndpoint) []string {
	if ctrl.srcIP == "" || ctrl.dstIP == "" {
		return nil
	}
	var expected, actual, role string
	switch n.kind {
	case "227":
		expected, actual, role = ctrl.dstIP, n.ip, "服务器(PASV 227)"
	case "PORT":
		expected, actual, role = ctrl.srcIP, n.ip, "客户端(PORT)"
	case "EPRT":
		expected, actual, role = ctrl.srcIP, n.ip, "客户端(EPRT)"
	default: // "229"(EPSV)不含地址,无角色可比对
		return nil
	}
	if actual == expected {
		return nil
	}
	return []string{fmt.Sprintf(
		"flow %q 的 %s 协商地址 %s 与控制连接 %s 端 %s 不一致(协商地址与控制连接角色不匹配)",
		n.flowName, n.kind, actual, role, expected)}
}

// matchNegotiation 在除控制流外的 flow 中查找 dst IP:dport 与协商端点一致的数据流。
// 完全一致 → 无告警;仅端口或仅 IP 一致 → 给出指向性告警;都不一致 → 告警未找到对应数据流。
// 对 229(EPSV):ip 为空,地址隐式为控制连接对端(服务器侧=控制流 dst IP),故比对时
// 把 n.ip 补为 ctrl.dstIP,再按"完全一致 / 端口一致 / IP 一致 / 未找到"判定。
func matchNegotiation(n ftpNegotiation, flows []FlowSpec, eps []flowEndpoint, ctrlIdx int) []string {
	// 229(EPSV)不含地址:隐式为控制连接服务器侧(ctrl.dstIP)。补上后再比对。
	if n.kind == "229" && n.ip == "" {
		n.ip = eps[ctrlIdx].dstIP
	}
	var portMatch, ipMatch []string
	for k := range flows {
		if k == ctrlIdx || eps[k].dstIP == "" {
			continue
		}
		if eps[k].dport == n.port {
			if eps[k].dstIP == n.ip {
				return nil // 完全一致
			}
			portMatch = append(portMatch, fmt.Sprintf("flow %q 的 dst %s:%d", flowLabel(flows[k].Name, k), eps[k].dstIP, eps[k].dport))
		} else if eps[k].dstIP == n.ip {
			ipMatch = append(ipMatch, fmt.Sprintf("flow %q 的 dst %s:%d", flowLabel(flows[k].Name, k), eps[k].dstIP, eps[k].dport))
		}
	}
	switch {
	case len(portMatch) > 0:
		return []string{fmt.Sprintf(
			"flow %q 的 %s 协商数据连接 %s:%d,但 %s:端口一致而 IP 不一致(端口协商与数据连接不一致)",
			n.flowName, n.kind, n.ip, n.port, strings.Join(portMatch, "、"))}
	case len(ipMatch) > 0:
		return []string{fmt.Sprintf(
			"flow %q 的 %s 协商数据连接 %s:%d,但 %s:IP 一致而端口不一致(端口协商与数据连接不一致)",
			n.flowName, n.kind, n.ip, n.port, strings.Join(ipMatch, "、"))}
	default:
		return []string{fmt.Sprintf(
			"flow %q 的 %s 协商数据连接 %s:%d,但未找到 dst 为 %s:%d 的数据流(端口协商与数据连接不一致)",
			n.flowName, n.kind, n.ip, n.port, n.ip, n.port)}
	}
}

// parseFTPPortTuple 从文本解析 FTP 六元组为 IPv4 + 端口。优先匹配带括号形式(227),
// 再回退裸六元组(PORT args)。分量越界(>255)视为解析失败。
func parseFTPPortTuple(text string) (ip string, port uint16, ok bool) {
	m := ftpPortTupleRegex.FindStringSubmatch(text)
	if m == nil {
		m = portArgsRegex.FindStringSubmatch(text)
	}
	if m == nil {
		return "", 0, false
	}
	var b [4]int
	for i := range 4 {
		v, err := strconv.Atoi(m[1+i])
		if err != nil || v < 0 || v > 255 {
			return "", 0, false
		}
		b[i] = v
	}
	var p [2]int
	for i := range 2 {
		v, err := strconv.Atoi(m[5+i])
		if err != nil || v < 0 || v > 255 {
			return "", 0, false
		}
		p[i] = v
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]), uint16(p[0]*256 + p[1]), true
}

// ftpNegotiationKind 取文本首 token,判定是否为协商命令/响应码(227/229/PORT/EPRT,大小写不敏感)。
// 用于原始 payload/payload_hex 文本的识别,避免把 220/331/150 等其它响应或 PASV/RETR
// 等命令误当作协商。
func ftpNegotiationKind(text string) (kind string, ok bool) {
	t := strings.TrimLeft(text, " \t")
	end := len(t)
	for i, r := range t {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			end = i
			break
		}
	}
	tok := t[:end]
	switch {
	case tok == "227":
		return "227", true
	case tok == "229":
		return "229", true
	case strings.EqualFold(tok, "PORT"):
		return "PORT", true
	case strings.EqualFold(tok, "EPRT"):
		return "EPRT", true
	}
	return "", false
}

// parseEPSVTuple 从 229(EPSV)响应文本解析端口。格式 (|||port|)(RFC 2428)。
// 仅提取端口:EPSV 不携带地址(地址隐式为控制连接对端)。
func parseEPSVTuple(text string) (port uint16, ok bool) {
	m := epsvTupleRegex.FindStringSubmatch(text)
	if m == nil {
		return 0, false
	}
	v, err := strconv.Atoi(m[1])
	if err != nil || v < 1 || v > 65535 {
		return 0, false
	}
	return uint16(v), true
}

// parseEPRTArgs 从 EPRT 请求 args 解析地址 + 端口。格式 |netproto|addr|port|(RFC 2428)。
// netproto=1(IPv4)/2(IPv6);addr 按对应地址族校验合法,返回 net.IP 的规范文本形式
// (归一化,避免同地址的不同文本表示被误判为不一致)。netproto 非 1/2 视为解析失败。
// 先剥首尾空白与 CRLF 行尾;原始 payload/payload_hex 文本首 token 为 EPRT 时,整行
// (含 \r\n 与 "EPRT " 命令前缀)会原样传入,而 ftp_request.args 字段已剥去命令前缀,
// 故这里统一剥去可能存在的 "EPRT" 命令前缀后再匹配(正则锚定行首,前缀会致失配)。
func parseEPRTArgs(text string) (ip string, port uint16, ok bool) {
	s := strings.TrimSpace(text)
	if strings.HasPrefix(strings.ToUpper(s), "EPRT") {
		s = strings.TrimSpace(s[4:])
	}
	m := eprtArgsRegex.FindStringSubmatch(s)
	if m == nil {
		return "", 0, false
	}
	netproto := m[1]
	addr := m[2]
	parsed := net.ParseIP(addr)
	switch {
	case netproto == "1" && parsed != nil && parsed.To4() != nil:
		ip = parsed.To4().String()
	case netproto == "2" && parsed != nil && parsed.To4() == nil:
		ip = parsed.To16().String()
	default:
		return "", 0, false
	}
	v, err := strconv.Atoi(m[3])
	if err != nil || v < 1 || v > 65535 {
		return "", 0, false
	}
	return ip, uint16(v), true
}

// normalizeFTPAddr 把 IPv4/IPv6 地址文本归一化为 net.IP 的规范文本形式
// (如 2001:db8:0:0:0:0:0:10 → 2001:db8::10),用于协商地址与 flow 端点地址比对时
// 消除同一地址不同文本表示的误判。无法解析的地址原样返回(不阻断,留给后续校验)。
func normalizeFTPAddr(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.To16().String()
}

// flowLabel 返回 flow 的告警定位标签:有名用名,无名用 "#<下标>"。
func flowLabel(name string, idx int) string {
	if name != "" {
		return name
	}
	return fmt.Sprintf("#%d", idx)
}
