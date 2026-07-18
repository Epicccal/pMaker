// Package scenario 定义声明式场景文件(YAML)的 schema、解析与校验。
//
// 每个 packet 是一个从外到内的有序 layer 栈(见 CLAUDE.md「封装与隧道」),
// 允许同类型重复(QinQ 双 VLAN)与递归嵌套(GRE 套报文)。
// 校验须尽早失败,报错带字段路径,便于非开发者定位问题。
//
// 时间表达通过 TimeSpec(绝对 ISO8601 或相对 base_time 的偏移)作用于
// base_time / packet.time / flow.start;PlannedPacket 是 scenario 模型 + 显式
// 时间戳的中间态,由 internal/plan 汇流排序后交 builder 序列化。
package scenario
