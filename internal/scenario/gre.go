package scenario

import (
	"fmt"
)

// 本文件集中 GRE 的 scenario 层校验(仿 vxlan.go):
//   - validateGREFields:单层规则(值域与互斥),由 validateLayer 调用
//     (packets / message.stack / quote.stack / flow.stack 三入口共用)
//   - validateGREPosition:跨层位置规则(前 IP 层、TEB 内层不额外限制),只在 packets
//     路径的 per-packet 循环里调用 —— flow 的位置约束由 flow_stack.go 的分段规则承载
//   - CheckGREWarnings:软告警(保留位非零、version 未知、PPTP/NVGRE 缺 key、ack 越界)

// ChecksumSet 报告 GRE C 位是否置位:checksum_present:true 或 checksum 字面值任一即置位
// (校验层、告警层与 builder 三处同口径,勿再手写该判定)。
func (f *GREFields) ChecksumSet() bool {
	return (f.ChecksumPresent != nil && *f.ChecksumPresent) || f.Checksum != nil
}

// validateGREFields 校验单层字段:值域、checksum 三态互斥、C=0 时 offset 不可写。
func validateGREFields(f *GREFields) error {
	for _, x := range []struct {
		name string
		v    uint32
		max  uint32
		why  string
	}{
		{"version", uint32(derefU8(f.Version)), 7, "3 位字段"},
		{"recursion", uint32(derefU8(f.Recursion)), 7, "3 位字段"},
		// flags 上限是 15 而非 RFC 1701 的 31:gopacket 把 Flags 的第 5 位(16<<3=0x80)
		// 编到与 Ack 相同的 bit 上,≥16 会静默点亮 A 位、凭空多出 4 字节 Ack 字段;
		// 15 以内恰是 RFC 2637 的 Flags 取值域(bits 9-12)全集,卡住无损。
		{"flags", uint32(derefU8(f.Flags)), 15, "上限 15 而非 RFC 1701 的 31:第 5 位与 Ack 标志位重叠,gopacket 编码会静默点亮 A 位凭空多出 4 字节 Ack 字段;要构造全 5 位保留位请用 payload_hex 整段手拼"},
	} {
		if x.v > x.max {
			return fmt.Errorf("gre.%s 超出值域 0-%d(%s),得到 %d", x.name, x.max, x.why, x.v)
		}
	}
	for _, x := range []struct {
		name string
		v    *Hex
	}{
		{"protocol", f.Protocol},
		{"checksum", f.Checksum},
		{"offset", f.Offset},
	} {
		if err := validateLengthRange(x.v, 16, "gre."+x.name); err != nil {
			return err
		}
	}
	if f.ChecksumPresent != nil && !*f.ChecksumPresent && f.Checksum != nil {
		return fmt.Errorf("gre.checksum_present: false 与 checksum 并存自相矛盾:C=0 时 Checksum 字段不上 wire,写了的值落不下去;请去掉 checksum 或置 checksum_present: true")
	}
	// C=0 时 Reserved1 字节根本不落(gopacket 由 C|R 驱动),非零 offset 会被静默吞掉;
	// C=1 时那两字节真上 wire,是可构造的畸形,只走软告警(CheckGREWarnings)。
	if !f.ChecksumSet() && f.Offset != nil && *f.Offset != 0 {
		return fmt.Errorf("gre.offset: Reserved1 仅在 C=1(checksum_present/checksum)时上 wire,C=0 时写了会被静默吞掉;请置 checksum_present: true 或去掉 offset")
	}
	return nil
}

// validateGREPosition 校验 standalone packet 栈中 gre 的位置:
//   - 前一层必须是 ipv4/ipv6(GRE 由 IP 协议 47 承载,不能直挂 eth);
//   - 后跟 eth(TEB/NVGRE 形态)时不额外限制内层结构,与 VXLAN「不查 inner eth 之后」
//     的口径一致。
func validateGREPosition(stack []Layer) error {
	for i, l := range stack {
		if _, ok := l.Fields.(*GREFields); !ok {
			continue
		}
		if i == 0 || (stack[i-1].Type != "ipv4" && stack[i-1].Type != "ipv6") {
			return fmt.Errorf("gre 前一层必须是 ipv4/ipv6(GRE 由 IP 协议 47 承载)")
		}
	}
	return nil
}

// derefU8 解引用可选 uint8,未写即 0。
func derefU8(p *uint8) uint8 {
	if p == nil {
		return 0
	}
	return *p
}

// CheckGREWarnings 扫描 packets 与 flows 的 GRE 层,产出软告警:
//   - gre.reserved-nonzero:version=0 下 recursion/flags 非零,或 C=1 时 offset 非零。
//     依据是发送侧的 MUST(RFC 1701 bits 5-12 传零、RFC 2784 Reserved1 传零),
//     不是「收端会丢包」(RFC 2784 的 MUST discard 只管 bits 1-5,bits 6-12 收端 ignore)。
//   - gre.version-unknown:version ∈ 2-7(RFC 2784 规定 MUST 为 0;1 是 RFC 2637 的合法扩展)。
//   - gre.pptp-missing-key:version=1 且未写 key(RFC 2637 §4.1 K 位须置 1)。
//   - gre.ack-outside-v1:version ≠ 1 却写了 ack(A 位由 RFC 2637 定义,v0 无此字段)。
//   - gre.nvgre-missing-key:显式写了 protocol: 0x6558 且未写 key(RFC 7637 K 位须置 1)。
//     只认显式声明:TEB(RFC 1701)是通用以太桥接承载,内层为 eth 自动推出 0x6558 的
//     GRE-over-Ethernet / ERSPAN 场景不要求 Key,按内层触发会让普通 TEB 场景平白挨告警。
func CheckGREWarnings(s *Scenario) []Diagnostic {
	if s == nil {
		return nil
	}
	var ws []Diagnostic
	check := func(f *GREFields, path, label string) {
		v := derefU8(f.Version)
		if v != 1 { // PPTP 下 Recur/Flags 语义由 RFC 2637 定义,不套 1701 的保留位口径
			if r := derefU8(f.Recursion); r != 0 {
				ws = append(ws, warnf(CodeGREReservedNonzero, path+".recursion",
					"%s.recursion: Recur=%d 非零;RFC 1701 规定 bits 5-12 MUST 传零(发送侧义务,收端 ignore);确属故意的畸形用例可忽略", label, r))
			}
			if fl := derefU8(f.Flags); fl != 0 {
				ws = append(ws, warnf(CodeGREReservedNonzero, path+".flags",
					"%s.flags: 保留位=%d 非零;RFC 1701 规定 bits 5-12 MUST 传零(发送侧义务,收端 ignore);确属故意的畸形用例可忽略", label, fl))
			}
		}
		if f.ChecksumSet() && f.Offset != nil && *f.Offset != 0 {
			ws = append(ws, warnf(CodeGREReservedNonzero, path+".offset",
				"%s.offset: Reserved1=0x%x 非零;RFC 2784 §2.1 规定该字段若存在 MUST 传零;确属故意的畸形用例可忽略", label, *f.Offset))
		}
		if v >= 2 && v <= 7 {
			ws = append(ws, warnf(CodeGREVersionUnknown, path+".version",
				"%s.version=%d:RFC 2784 规定 Version MUST 为 0(1 是 RFC 2637 PPTP 扩展);照常出包,收端大概率丢弃", label, v))
		}
		if v == 1 && f.Key == nil {
			ws = append(ws, warnf(CodeGREPPTPMissingKey, path+".key",
				"%s: version=1(PPTP,RFC 2637 §4.1)要求 K 位置 1,请写 key(高 2 字节=载荷长度,低 2 字节=Call ID)", label))
		}
		if v != 1 && f.Ack != nil {
			ws = append(ws, warnf(CodeGREAckOutsideV1, path+".ack",
				"%s.ack: Acknowledgment Number 由 RFC 2637 定义,仅 version=1(PPTP)有此字段;version=0 下收端不识别,确属故意可忽略", label))
		}
		if f.Protocol != nil && *f.Protocol == 0x6558 && f.Key == nil {
			ws = append(ws, warnf(CodeGRENVGEMissingKey, path+".key",
				"%s: protocol=0x6558 且未写 key;NVGRE(RFC 7637 §3.2)要求 K 位置 1(Key=VSID|FlowID);若只是 TEB 桥接(RFC 1701,不要求 Key)可忽略本告警", label))
		}
	}
	for i, p := range s.Packets {
		for j, l := range p.Stack {
			if f, ok := l.Fields.(*GREFields); ok {
				check(f, packetStackPath(i, j), fmt.Sprintf("packets[%d].stack[%d].gre", i, j))
			}
		}
	}
	for i, fl := range s.Flows {
		for j, l := range fl.Stack {
			if f, ok := l.Fields.(*GREFields); ok {
				check(f, flowStackPath(i, j), fmt.Sprintf("flows[%d](%s).stack[%d].gre", i, flowLabel(fl.Name, i), j))
			}
		}
	}
	return ws
}
