package builder

import (
	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// greProtoFor 在 ethTypeFor 之上补 eth → 0x6558(TEB):GRE 可直接承载以太帧
// (RFC 1701 Protocol Type 表),而 eth/vlan 层的下一层不可能是 eth,故不并入共享表
// (并入会让 vlan 后跟 eth 从报错变成静默 0x6558)。
func greProtoFor(next string) (layers.EthernetType, error) {
	if next == "eth" {
		return layers.EthernetTypeTransparentEthernetBridging, nil
	}
	return ethTypeFor(next)
}

// buildGRE 把 GREFields 落到 layers.GRE:可选字段写即置位(presence-driven);
// checksum 三态在 builder.go 的 add 闭包里按 f.Checksum 是否为 nil 分流(自动算 vs 原样落)。
func buildGRE(f *scenario.GREFields, next string) (*layers.GRE, error) {
	et, err := greProtoFor(next)
	if err != nil {
		return nil, err
	}
	g := &layers.GRE{Protocol: et}
	if f.Protocol != nil { // 显式覆盖(PPTP 0x880B、ERSPAN 0x88BE 等表外值,或断链畸形)
		g.Protocol = layers.EthernetType(uint16(*f.Protocol))
	}
	if f.Key != nil {
		g.KeyPresent, g.Key = true, uint32(*f.Key)
	}
	if f.Seq != nil {
		g.SeqPresent, g.Seq = true, *f.Seq
	}
	if f.Ack != nil {
		g.AckPresent, g.Ack = true, *f.Ack
	}
	// checksum 三态:显式值或 checksum_present 任一存在即 C=1;值交给 add 闭包分流
	if f.ChecksumSet() {
		g.ChecksumPresent = true
	}
	if f.Checksum != nil {
		g.Checksum = uint16(*f.Checksum)
	}
	if f.Offset != nil { // Reserved1,仅 C=1 时上 wire(校验层已拦 C=0 非零)
		g.Offset = uint16(*f.Offset)
	}
	if f.Version != nil {
		g.Version = *f.Version
	}
	if f.Recursion != nil {
		g.RecursionControl = *f.Recursion
	}
	if f.Flags != nil {
		g.Flags = *f.Flags
	}
	return g, nil
}
