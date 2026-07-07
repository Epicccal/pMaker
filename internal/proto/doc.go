// Package proto 提供各协议与封装层的构造助手,优先复用 gopacket 现成 layer。
//
// 覆盖以太/VLAN/QinQ/GRE/MPLS/VXLAN 等封装层,以及 IP/TCP/UDP/DNS 等协议层。
// 封装层须实现 next-proto / EtherType 的自动推导,并允许逐层显式覆盖(构造非标/畸形封装)。
package proto
