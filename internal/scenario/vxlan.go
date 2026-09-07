package scenario

import "fmt"

// 本文件集中 VXLAN 的 scenario 层校验:
//   - validateVXLANFields:单层规则(VNI 24 位值域),由 validateLayer 调用
//   - validateVXLANPosition:跨层位置规则(前 udp、后 inner eth),在 Validate 的
//     per-packet 循环里对每个 stack 调一次 —— validateLayer 只见单层看不到邻居,
//     位置规则须 stack 级遍历承载(与 validateFlow 的 vlan 前后向扫描同构)
//
// 不校验 inner eth 之后的内容(双 eth、内层结构畸形等),与 GRE 内层不查的口径一致;
// 畸形内容走既有 payload/payload_hex 兜底。

// validateVXLANFields 校验 VNI 值域:24 位字段,uint32 底层放得下 25-32 位值,
// 但语义上超出 24 位会在 wire 上与保留位混淆,故在 scenario 层拦截。
func validateVXLANFields(f *VXLANFields) error {
	if f.VNI > 0xFFFFFF {
		return fmt.Errorf("vxlan.vni 超出 24 位: %d", f.VNI)
	}
	return nil
}

// validateVXLANPosition 校验 standalone packet 栈中 vxlan 的位置:
//   - 前一层必须是 udp(VXLAN 头由 UDP 承载,无挂靠即报错)
//   - 后一层必须是 inner eth(VXLAN 后必须是以太帧)
func validateVXLANPosition(stack []Layer) error {
	for i, l := range stack {
		if _, ok := l.Fields.(*VXLANFields); !ok {
			continue
		}
		if i == 0 || stack[i-1].Type != "udp" {
			return fmt.Errorf("vxlan 前一层必须是 udp")
		}
		if i+1 >= len(stack) || stack[i+1].Type != "eth" {
			return fmt.Errorf("vxlan 后必须紧跟 inner eth")
		}
	}
	return nil
}
