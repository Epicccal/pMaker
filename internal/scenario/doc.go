// Package scenario 定义声明式场景文件(YAML)的 schema、解析与校验。
//
// 每个 packet 是一个从外到内的有序 layer 栈(见 CLAUDE.md「封装与隧道」),
// 允许同类型重复(QinQ 双 VLAN)与递归嵌套(GRE 套报文)。
// 校验须尽早失败,报错带字段路径,便于非开发者定位问题。
package scenario
