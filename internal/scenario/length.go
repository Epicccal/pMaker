package scenario

import "fmt"

// 本文件集中 length 覆盖的 scenario 层逻辑,与 checksum.go 对称:
//   - hasLengthOverride:报言层是否显式写了任意长度覆盖字段(flow 展开器会丢弃,故需拦截)
//   - validateLengthRange:按字段宽度做值域校验(Hex 底层是 uint32,越界会被 builder 的
//     uint16/uint8 转换静默截断 —— 4 位字段尤其危险,会溢出污染相邻半字节)
//
// 两态语义:写即覆盖(原样落值,关闭该层自动长度修正)、不写即自动计算。与 checksum 同构。

// hasLengthOverride 报告该层是否显式写了任意长度覆盖字段。flow 展开器(parseFlowStack)
// 按连接状态重建各层字段结构体,只搬 port/seq/ack/ip/ttl/mss,这些长度字段直接丢弃,
// 故 flow.stack 上一旦写长度覆盖即静默无效;validateFlow 据此先于 validateLayer 拦截
// 并引导改用 standalone packet。
func hasLengthOverride(l Layer) bool {
	switch f := l.Fields.(type) {
	case *IPv4Fields:
		return f.Length != nil || f.IHL != nil
	case *IPv6Fields:
		return f.PayloadLength != nil
	case *TCPFields:
		return f.DataOffset != nil
	case *UDPFields:
		return f.Length != nil
	}
	return false
}

// validateLengthRange 校验显式覆盖的长度值域。bits 为字段位宽(16 或 4):
//   - 16 位字段(ipv4 总长度 / ipv6 载荷长度 / udp 长度):上限 0xFFFF;
//   - 4 位字段(ihl / data_offset):上限 0xF —— 用 16 位上限放行会在 builder 的
//     uint8 转换里静默截断,或在与 Version 拼接的 (Version<<4)|IHL 里溢出污染 Version
//     半字节,把 IP 版本号打成 4 以外的值而用户以为自己只动了 IHL。
//
// nil 表示未覆盖,直接放行(走自动计算路径)。
func validateLengthRange(v *Hex, bits uint, name string) error {
	if v == nil {
		return nil
	}
	max := uint32(1)<<bits - 1
	if uint32(*v) > max {
		return fmt.Errorf("%s 超出 %d 位: 0x%x", name, bits, *v)
	}
	return nil
}
