package scenario

import "fmt"

// 本文件集中 VLAN 字段值域的 scenario 层校验,与 checksum.go / length.go 对称:
//   - validateVLANVID:12 位 VID 值域(uint16 字段本身放得下,但 vid 语义上限 0xFFF)
//   - tpid/type 的 16 位值域校验复用 length.go 的 validateLengthRange(Hex 底层是 uint32,
//     越界会被 builder 的 uint16 转换静默截断)

// validateVLANVID 校验 VLAN VID 值域:VID 是 12 位字段,上限 0xFFF。
// VID 0(priority tag)与 4095(保留值)按字段表达能力放行 —— 非标 VID 是合法的
// 畸形构造意图;校验只拦截"12 位里根本放不下"的值,与 wire 上能表达的值域一致。
func validateVLANVID(v uint16) error {
	if v > 0xFFF {
		return fmt.Errorf("vlan.vid 超出 12 位: %d", v)
	}
	return nil
}
