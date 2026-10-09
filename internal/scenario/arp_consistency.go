package scenario

import (
	"fmt"
	"net"
)

// CheckARPWarnings 扫描 packets 的 ARP 层,产出软告警。判断一律用字段缺省填充后的
// 线上值:省略 sender_proto_addr 与显式写 0.0.0.0 落线逐位相同,按文本比较会漏告警。
//   - arp.gratuitous:sender_proto_addr == target_proto_addr(Gratuitous ARP,RFC 5227)
//   - arp.probe:sender_proto_addr == 0.0.0.0(ARP Probe,RFC 5227 冲突检测)
//   - arp.request-non-zero-target-hw:request(op=1)但 target_hw_addr 非全零
//   - arp.length-mismatch:hardware_length/protocol_length 与地址字段实际长度不符
func CheckARPWarnings(s *Scenario) []Diagnostic {
	if s == nil {
		return nil
	}
	var ws []Diagnostic
	for i, p := range s.Packets {
		for j, l := range p.Stack {
			f, ok := l.Fields.(*ARPLayer)
			if !ok {
				continue
			}
			path := packetStackPath(i, j)
			label := fmt.Sprintf("packets[%d].stack[%d].arp", i, j)
			ws = append(ws, checkARPLayer(f, path, label)...)
		}
	}
	return ws
}

func checkARPLayer(f *ARPLayer, path, label string) []Diagnostic {
	var ws []Diagnostic

	// 省略字段由 builder 落全零,线上值与显式写 0.0.0.0 逐位相同:
	// 两处比较都归一后再判,否则省略写法静默逃过检查(告警只看声明文本 = 看错对象)。
	sender := f.SenderProtoAddr
	if sender == "" {
		sender = "0.0.0.0"
	}

	if f.TargetProtoAddr != "" && sender == f.TargetProtoAddr {
		ws = append(ws, warnf(CodeARPGratuitous, path+".sender_proto_addr",
			"%s: sender_proto_addr == target_proto_addr(%s),这是 Gratuitous ARP(RFC 5227);若属故意可忽略", label, f.TargetProtoAddr))
	}

	if sender == "0.0.0.0" {
		ws = append(ws, warnf(CodeARPProbe, path+".sender_proto_addr",
			"%s: sender_proto_addr=0.0.0.0,这是 ARP Probe(RFC 5227 §2.1 冲突检测);若属故意可忽略", label))
	}

	if f.Operation != nil && *f.Operation == 1 {
		tgt := f.TargetHWAddr
		if tgt == "" {
			tgt = "00:00:00:00:00:00"
		}
		hw, err := net.ParseMAC(tgt)
		if err == nil && !isZeroMAC(hw) {
			ws = append(ws, warnf(CodeARPRequestNonZeroTgtHW, path+".target_hw_addr",
				"%s: operation=1(Request)但 target_hw_addr=%s 非全零;ARP Request 的目标 MAC 通常为全零;若属故意可忽略", label, tgt))
		}
	}

	// 长度不匹配:仅在显式覆盖时校验
	if f.HardwareLength != nil {
		senderHW := f.SenderHWAddr
		if senderHW == "" {
			senderHW = "00:00:00:00:00:00"
		}
		hw, err := net.ParseMAC(senderHW)
		if err == nil && int(*f.HardwareLength) != len(hw) {
			ws = append(ws, warnf(CodeARPLengthMismatch, path+".hardware_length",
				"%s: hardware_length=%d 但 MAC 地址实际长度=%d;若属故意畸形可忽略", label, *f.HardwareLength, len(hw)))
		}
	}
	if f.ProtocolLength != nil {
		addr := f.SenderProtoAddr
		if addr == "" {
			addr = "0.0.0.0"
		}
		ip := net.ParseIP(addr).To4()
		if ip != nil && int(*f.ProtocolLength) != len(ip) {
			ws = append(ws, warnf(CodeARPLengthMismatch, path+".protocol_length",
				"%s: protocol_length=%d 但 IPv4 地址实际长度=%d;若属故意畸形可忽略", label, *f.ProtocolLength, len(ip)))
		}
	}

	return ws
}

func isZeroMAC(hw net.HardwareAddr) bool {
	for _, b := range hw {
		if b != 0 {
			return false
		}
	}
	return true
}
