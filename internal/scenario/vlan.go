package scenario

import "fmt"

// 本文件集中 VLAN 字段值域的 scenario 层校验,与 checksum.go / length.go 对称:
//   - validateVLANVID:12 位 VID 值域(uint16 字段本身放得下,但 vid 语义上限 0xFFF)
//   - validateVLANPri:3 位 PCP 值域(0-7)
//   - type 的 16 位值域校验复用 length.go 的 validateLengthRange(Hex 底层是 uint32,
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

// validateVLANPri 校验 PCP 值域:PCP 是 TCI 高 3 位(0-7)。uint8 字段本身放得下 8-255,
// 但语义上超出 3 位会在 wire 上与 DEI/VID 位混淆,故在 scenario 层拦截(与 vid 同口径:
// 拦"字段语义放不下",不拦"非标但 wire 能表达")。
func validateVLANPri(v uint8) error {
	if v > 7 {
		return fmt.Errorf("vlan.pri 超出 3 位(PCP 值域 0-7): %d", v)
	}
	return nil
}

// validateVLANFields 校验一个 vlan 层的全部字段。inFlow 表示该层来自 flow.stack
// ——只有 flow.stack 有方向语义(展开器按 message.from 的 src/dst 决定方向),
// standalone packets / message.stack 逐包自带完整 stack,方向差异直接写两个包即可。
func validateVLANFields(f *VLANFields, inFlow bool) error {
	if f.SrcVID == nil && f.DstVID == nil {
		if err := validateVLANVID(f.VID); err != nil {
			return err
		}
	} else {
		if err := validateVLANDirectionalVID(f, inFlow); err != nil {
			return err
		}
	}
	if f.Pri != nil {
		if err := validateVLANPri(*f.Pri); err != nil {
			return err
		}
	}
	return validateLengthRange(f.Type, 16, "vlan.type")
}

// validateVLANDirectionalVID 校验方向化 VID(src_vid/dst_vid)的适用范围、与 vid 的互斥
// 及各自值域。只在至少一个方向字段非 nil 时调用。
//
// 与 vid 互斥:两种写法并存时,哪个方向落哪个值无唯一解释,静默取其一会生成与配置不符的包
// (与全项目「拒绝静默坏包」一致)。`vid: 0` 的零值与"未写"不可区分,故只以 vid != 0 判冲突。
func validateVLANDirectionalVID(f *VLANFields, inFlow bool) error {
	if !inFlow {
		return fmt.Errorf("vlan.src_vid/dst_vid 只在 flow.stack 内有效(standalone packets 与 message.stack 无方向语义,改用 vlan.vid;需要方向差异就逐包写 stack)")
	}
	if f.VID != 0 {
		return fmt.Errorf("vlan.vid 与 vlan.src_vid/dst_vid 互斥(两向同 VID 只写 vid;两向不同就只写 src_vid/dst_vid)")
	}
	if f.SrcVID != nil {
		if err := validateVLANVID(*f.SrcVID); err != nil {
			return fmt.Errorf("vlan.src_vid: %w", err)
		}
	}
	if f.DstVID != nil {
		if err := validateVLANVID(*f.DstVID); err != nil {
			return fmt.Errorf("vlan.dst_vid: %w", err)
		}
	}
	return nil
}
