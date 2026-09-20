package scenario

import (
	"fmt"
	"slices"
	"strings"
)

// 本文件承载 tftp 层的五条一致性软告警。所有检查照常出包、不阻断:
// 畸形用例可能故意构造不一致(端口不指 69、超长 DATA、无关字段),
// 与硬错(validateTFTPFields)的分界见 diagnostic.go 的异常模型说明。

// tftpRef 是一个 tftp 层在场景里的定位:字段指针、声明级路径、告警定位文案,
// 以及 RQ 端口检查所需的上下文(所在 stack 与消息方向)。
type tftpRef struct {
	f       *TFTPFields
	path    string  // 声明级字段路径
	label   string  // 告警文案里的人读定位
	udpIn   []Layer // udp 层的查找范围:standalone = 自身 stack;flow = flow.stack
	fromSrc bool    // flow 消息 from: src?standalone 恒 true(报文即声明方向)
}

// collectTFTPLayers 收集场景里全部 tftp 层的定位。flow 中 from: dst 的消息端点已交换
// (dport 是客户端 TID,不是服务器端口),不参与 RQ 端口检查,但其余检查照常。
func collectTFTPLayers(s *Scenario) []tftpRef {
	var refs []tftpRef
	for i, p := range s.Packets {
		for j, l := range p.Stack {
			if f, ok := l.Fields.(*TFTPFields); ok {
				refs = append(refs, tftpRef{
					f: f, path: packetStackPath(i, j),
					label: fmt.Sprintf("packets[%d].stack[%d]", i, j),
					udpIn: p.Stack, fromSrc: true,
				})
			}
		}
	}
	for i, fl := range s.Flows {
		for k, m := range fl.Messages {
			for j, l := range m.Stack {
				f, ok := l.Fields.(*TFTPFields)
				if !ok {
					continue
				}
				refs = append(refs, tftpRef{
					f: f, path: flowMessageStackPath(i, k, j),
					label: fmt.Sprintf("flows[%d](%s).messages[%d].stack[%d]", i, flowLabel(fl.Name, i), k, j),
					udpIn: fl.Stack, fromSrc: m.From == "src",
				})
			}
		}
	}
	return refs
}

// CheckTFTPRQPort 检查 RRQ/WRQ 的目标端口(RFC 1350 服务器监听 69)。
// flow 中 from: dst 的消息端点已交换,不检查;找不到 UDP 层不告警。
func CheckTFTPRQPort(s *Scenario) []Diagnostic {
	var ws []Diagnostic
	for _, r := range collectTFTPLayers(s) {
		op, err := ParseTFTPOpcode(r.f.Opcode)
		if err != nil || (op != 1 && op != 2) || !r.fromSrc {
			continue
		}
		var udp *UDPFields
		for _, l := range r.udpIn {
			if u, ok := l.Fields.(*UDPFields); ok {
				udp = u // 取最后一个(最靠近载荷的)UDP 层,VXLAN 双 UDP 栈不误取 outer
			}
		}
		if udp == nil || udp.DPort == 69 {
			continue
		}
		ws = append(ws, warnf(CodeTFTPRQPort, r.path,
			"%s: %s 的 UDP dport 是 %d,RFC 1350 规定 RRQ/WRQ 发往服务器 69 端口;故意构造可忽略本告警",
			r.label, tftpOpcodeName(op), udp.DPort))
	}
	return ws
}

// CheckTFTPModeObsolete 检查已废弃的 mode "mail"(RFC 1350 Appendix II)。
// 判定前做小写折叠(RFC 1350 §1 mode 大小写不敏感),wire 落用户写的原值。
func CheckTFTPModeObsolete(s *Scenario) []Diagnostic {
	var ws []Diagnostic
	for _, r := range collectTFTPLayers(s) {
		op, err := ParseTFTPOpcode(r.f.Opcode)
		if err != nil || (op != 1 && op != 2) || r.f.Mode == "" {
			continue
		}
		if strings.ToLower(r.f.Mode) != "mail" {
			continue
		}
		ws = append(ws, warnf(CodeTFTPModeObsolete, r.path,
			"%s: mode %q 是已废弃的 mail 模式(RFC 1350 Appendix II,后续修订删除);畸形用例可故意构造,正常场景请用 octet/netascii",
			r.label, r.f.Mode))
	}
	return ws
}

// CheckTFTPModeUnknown 检查不在已知集合 {octet, netascii, mail} 里的 mode(如 binary)。
// 折叠后命中 octet/netascii 大小写变体不告警——RFC 1350 §1 明文允许大小写不敏感。
func CheckTFTPModeUnknown(s *Scenario) []Diagnostic {
	var ws []Diagnostic
	for _, r := range collectTFTPLayers(s) {
		op, err := ParseTFTPOpcode(r.f.Opcode)
		if err != nil || (op != 1 && op != 2) || r.f.Mode == "" {
			continue
		}
		switch strings.ToLower(r.f.Mode) {
		case "octet", "netascii", "mail":
			continue
		}
		ws = append(ws, warnf(CodeTFTPModeUnknown, r.path,
			"%s: mode %q 不在已知集合 {octet, netascii, mail} 里;照常出包,接收端多半按 netascii/octet 解释失败",
			r.label, r.f.Mode))
	}
	return ws
}

// CheckTFTPDataSize 检查 DATA 载荷是否超过 512 字节(RFC 1350 默认 block_size)。
// 超长块让接收端无法靠「末块长度 < blksize」判断传输结束。
// 场景里若协商了 blksize 选项,以协商值为准(本检查不跨包追踪协商,恒按 512 基准提示)。
func CheckTFTPDataSize(s *Scenario) []Diagnostic {
	var ws []Diagnostic
	for _, r := range collectTFTPLayers(s) {
		op, err := ParseTFTPOpcode(r.f.Opcode)
		if err != nil || op != 3 {
			continue
		}
		n := len(r.f.Data)
		if r.f.DataHex != "" {
			b, err := ParsePayloadHex(r.f.DataHex)
			if err != nil {
				continue // 校验阶段已拦,防御性跳过
			}
			n = len(b)
		}
		if n <= 512 {
			continue
		}
		ws = append(ws, warnf(CodeTFTPDataOversize, r.path,
			"%s: DATA 载荷 %d 字节超过 RFC 1350 默认 block_size 512,接收端无法据此判断传输结束;若配置了 blksize 选项请以协商值为准",
			r.label, n))
	}
	return ws
}

// tftpValidFields 返回 opcode 的有效字段集(不含 opcode 本身);未知数字 opcode 返回 nil。
func tftpValidFields(op uint16) map[string]bool {
	switch op {
	case 1, 2: // rrq / wrq
		return map[string]bool{"filename": true, "mode": true, "options": true}
	case 3: // data
		return map[string]bool{"block": true, "data": true, "data_hex": true}
	case 4: // ack
		return map[string]bool{"block": true}
	case 5: // error
		return map[string]bool{"code": true, "message": true}
	case 6: // oack
		return map[string]bool{"options": true}
	}
	return nil
}

// CheckTFTPFieldIgnored 检查与 opcode 无关的字段——序列化时被静默忽略,提前提示可省调试。
// 故意写无关字段是合法畸形用例,故只告警不硬错。
func CheckTFTPFieldIgnored(s *Scenario) []Diagnostic {
	var ws []Diagnostic
	for _, r := range collectTFTPLayers(s) {
		op, err := ParseTFTPOpcode(r.f.Opcode)
		if err != nil {
			continue
		}
		f := r.f
		written := []string{}
		for name, set := range map[string]bool{
			"filename": f.Filename != "",
			"mode":     f.Mode != "",
			"options":  len(f.Options) > 0,
			"block":    f.Block != nil,
			"data":     f.Data != "",
			"data_hex": f.DataHex != "",
			"code":     f.Code.Kind != 0 && f.Code.Value != "",
			"message":  f.Message != "",
		} {
			if set {
				written = append(written, name)
			}
		}
		valid := tftpValidFields(op)
		var ignored []string
		for _, name := range written {
			if valid == nil || !valid[name] {
				ignored = append(ignored, name)
			}
		}
		if len(ignored) == 0 {
			continue
		}
		slices.Sort(ignored)
		ws = append(ws, warnf(CodeTFTPFieldIgnored, r.path,
			"%s: 字段 %s 与 opcode=%s 无关(仅 %s 类报文有效),序列化时被忽略;故意构造可忽略本告警",
			r.label, strings.Join(ignored, ", "), tftpOpcodeName(op), fieldOwnerHint(ignored)))
	}
	return ws
}

// fieldOwnerHint 给出被忽略字段的有效 opcode 文案(告警提示用)。
func fieldOwnerHint(ignored []string) string {
	owner := map[string]string{
		"filename": "rrq/wrq", "mode": "rrq/wrq", "options": "rrq/wrq/oack",
		"block": "data/ack", "data": "data", "data_hex": "data",
		"code": "error", "message": "error",
	}
	var hints []string
	for _, name := range ignored {
		hints = append(hints, owner[name])
	}
	return strings.Join(hints, "/")
}
