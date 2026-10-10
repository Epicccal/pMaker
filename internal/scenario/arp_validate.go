package scenario

import (
	"fmt"
	"net"
)

// 本文件集中 ARP 的 scenario 层校验:
//   - validateARPFields:单层硬错校验(必填字段、格式),由 validateLayer 调用

// validateARPFields 校验 ARP 层字段:
//   - operation 必填
//   - target_proto_addr 必填且为 IPv4(用 To4 判,net.ParseIP 对 IPv6 同样非 nil)
//   - sender_hw_addr / target_hw_addr 若非空须为合法 MAC
//   - sender_proto_addr 若非空须为合法 IPv4
func validateARPFields(f *ARPLayer) error {
	if f.Operation == nil {
		return fmt.Errorf("arp.operation: 必填(1=Request, 2=Reply, 3=RARP Request, 4=RARP Reply)")
	}
	if f.TargetProtoAddr == "" {
		return fmt.Errorf("arp.target_proto_addr: 必填")
	}
	if net.ParseIP(f.TargetProtoAddr).To4() == nil {
		return fmt.Errorf("arp.target_proto_addr: 非法 IPv4 地址 %q", f.TargetProtoAddr)
	}
	if f.SenderHWAddr != "" {
		if _, err := net.ParseMAC(f.SenderHWAddr); err != nil {
			return fmt.Errorf("arp.sender_hw_addr: 非法 MAC 地址 %q", f.SenderHWAddr)
		}
	}
	if f.TargetHWAddr != "" {
		if _, err := net.ParseMAC(f.TargetHWAddr); err != nil {
			return fmt.Errorf("arp.target_hw_addr: 非法 MAC 地址 %q", f.TargetHWAddr)
		}
	}
	if f.SenderProtoAddr != "" {
		if net.ParseIP(f.SenderProtoAddr).To4() == nil {
			return fmt.Errorf("arp.sender_proto_addr: 非法 IPv4 地址 %q", f.SenderProtoAddr)
		}
	}
	return nil
}
