package scenario

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// 本文件实现 FTP 控制通道 ↔ 数据通道的端口/IP 一致性告警(非硬错)。
//
// 背景:227(PASV)/PORT 协商文本里的六元组 (h1,h2,h3,h4,p1,h2) 声明了数据连接的
// IP:端口,而数据连接是另一条独立 flow,其 dst IP:dport 由用户另写。工具不强制两者
// 联动,一旦用户改了一处忘了另一处,产出的 pcap 就是"控制连接声明 50000、实际数据
// 连接去 49999"的不自洽场景——这会让 NDR 报"端口协商不一致"误报,而用户无从分辨是
// 配置错还是有意构造。本检查在校验阶段把这类不一致作为告警产出(warn 而非 error,
// 因为畸形用例可能故意构造不一致以测试 NDR)。
//
// 协商端点语义:227/PORT 六元组的 (ip, port) 始终是"被连接方"地址——
//   - PASV(227):服务器告知客户端"连我 ip:port",数据流 src=客户端、dst=服务器;
//   - PORT:客户端告知服务器"连我 ip:port",主动模式 stack 反转使客户端成为数据流 dst。
// 故两种模式下协商端点都等于数据流的 dst IPv4 : dport,统一按此比对。
//
// 只扫描"控制通道候选"flow(sport/dport==21 或含 ftp_request/ftp_response 层)的消息,
// 避免误扫数据流里恰好含 "227"/"PORT" 字样的文件内容。

// ftpPortTupleRegex 匹配带括号的六元组,用于 227 响应文本
// (如 "Entering Passive Mode (10,0,0,21,195,80).")。容忍分量间空白。
var ftpPortTupleRegex = regexp.MustCompile(`\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)`)

// portArgsRegex 匹配裸六元组(无括号、整串),用于 ftp_request PORT 的 args 字段
// (如 "10,0,0,10,192,5")。
var portArgsRegex = regexp.MustCompile(`^\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*$`)

// ftpNegotiation 是一条从 227/PORT 文本解析出的数据连接协商端点。
type ftpNegotiation struct {
	flowName string // 所在控制流名(空名则用 "#<下标>"),用于告警定位
	msgIdx   int    // 所在消息在 flow 内的序号,用于告警定位
	kind     string // "227" | "PORT"
	ip       string // 协商 IPv4(h1.h2.h3.h4)
	port     uint16 // 协商端口 p1*256+p2
}

// flowEndpoint 是一条 flow 用于匹配的端点摘要:最近的 IPv4 src/dst 与 TCP/UDP dport,
// 以及是否为控制通道候选。srcIP/dstIP 用于 FTP 协商地址 ↔ 控制连接角色校验。
type flowEndpoint struct {
	srcIP  string
	dstIP  string
	dport  uint16
	sport  uint16
	isCtrl bool
}

// CheckFTPDataPortConsistency 扫描 FTP 控制通道的 PASV 227 / PORT 协商,解析出协商的
// 数据连接 IP:端口,再与场景中各 flow 的 dst IPv4 : dport 比对。对解析失败、或协商端点
// 与数据流端点不一致的情况,产出告警(非硬错:畸形用例可能故意构造不一致以测试 NDR)。
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
				ep.srcIP = v.Src
				ep.dstIP = v.Dst
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
// 原始 payload/payload_hex 文本首 token 为 "227"/"PORT"),避免误判其它响应码或命令。
func extractFTPNegotiations(flowName string, msgIdx int, m Message) (negotiations []ftpNegotiation, parseWarnings []string) {
	if len(m.Stack) == 0 {
		return
	}
	// add 解析一段协商文本:成功则记端点,失败则记告警(用户选择"解析失败也提示")。
	add := func(kind, text string) {
		ip, port, ok := parseFTPPortTuple(text)
		if ok {
			negotiations = append(negotiations, ftpNegotiation{flowName, msgIdx, kind, ip, port})
			return
		}
		parseWarnings = append(parseWarnings, fmt.Sprintf(
			"flow %q 的 messages[%d] 的 %s 协商文本 %q 未解析出 IP:端口六元组,无法校验数据端口一致性",
			flowName, msgIdx, kind, text))
	}

	switch f := m.Stack[0].Fields.(type) {
	case *FTPResponseFields:
		if f.Code == 227 {
			// 227 文本可能在 message 或 lines(多行续行)里;合并扫描,以括号六元组为准。
			var b strings.Builder
			b.WriteString(f.Message)
			for _, ln := range f.Lines {
				if ln != "" {
					b.WriteByte(' ')
					b.WriteString(ln)
				}
			}
			add("227", b.String())
		}
	case *FTPRequestFields:
		if strings.EqualFold(f.Command, "PORT") {
			add("PORT", f.Args)
		}
	case *PayloadFields:
		// 原始 payload 文本:仅在首 token 为 227/PORT 时尝试,避免误扫文件内容。
		if kind, ok := ftpNegotiationKind(f.Payload); ok {
			add(kind, f.Payload)
		}
	case PayloadHex:
		// payload_hex 是原始字节;控制通道候选才扫到这里,解码后按文本同法判断。
		raw, err := ParsePayloadHex(string(f))
		if err != nil {
			return
		}
		text := string(raw)
		if kind, ok := ftpNegotiationKind(text); ok {
			add(kind, text)
		}
	}
	return
}

// checkNegotiationRole 校验 227/PORT 协商的 IP 是否为控制连接的一方端点。
//
// RFC 959 语义:
//   - PASV(227):服务器告知"连我 ip:port",故协商 IP 必须是控制连接的服务器侧
//     (dport=21 一方的 IPv4,即控制流 dst IP)。
//   - PORT:客户端告知"连我 ip:port",故协商 IP 必须是控制连接的客户端侧
//     (sport=21 一方的 IPv4,即控制流 src IP)。
//
// 协商 IP 与控制连接对应角色不一致时,声明的是与本次会话无关的地址(常见笔误或配置错),
// 产出告警。畸形用例可能故意构造不一致以测试 NDR,故只告警不阻断。
// 控制流缺 IPv4 端点信息时跳过(无法判定)。
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
	default:
		return nil
	}
	if actual == expected {
		return nil
	}
	return []string{fmt.Sprintf(
		"flow %q 的 %s 协商地址 %s 与控制连接 %s 端 %s 不一致(协商地址与控制连接角色不匹配)",
		n.flowName, n.kind, actual, role, expected)}
}

// matchNegotiation 在除控制流外的 flow 中查找 dst IPv4:dport 与协商端点一致的数据流。
// 完全一致 → 无告警;仅端口或仅 IP 一致 → 给出指向性告警;都不一致 → 告警未找到对应数据流。
func matchNegotiation(n ftpNegotiation, flows []FlowSpec, eps []flowEndpoint, ctrlIdx int) []string {
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

// ftpNegotiationKind 取文本首 token,判定是否为 227 响应或 PORT 命令(大小写不敏感)。
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
	case strings.EqualFold(tok, "PORT"):
		return "PORT", true
	}
	return "", false
}

// flowLabel 返回 flow 的告警定位标签:有名用名,无名用 "#<下标>"。
func flowLabel(name string, idx int) string {
	if name != "" {
		return name
	}
	return fmt.Sprintf("#%d", idx)
}
