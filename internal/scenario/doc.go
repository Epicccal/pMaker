// Package scenario 定义声明式场景文件(YAML)的 schema、解析与校验。
//
// 每个 packet 是一个从外到内的有序 layer 栈(见 CLAUDE.md「封装与隧道」),
// 允许同类型重复(QinQ 双 VLAN)与递归嵌套(GRE 套报文)。
// 校验须尽早失败,报错带字段路径,便于非开发者定位问题。
//
// 时间表达采用「base_time + offset_time」模型:base_time 是场景里唯一的绝对锚
// (AbsTime,仅 ISO8601),packet.offset_time / flow.offset_time 是相对它的时长
// 偏移(Offset,仅接受时长)。两者由各自类型在解析阶段结构性保证取值合法,
// 不再依赖运行期校验兜底。PlannedPacket 是 scenario 模型 + 显式时间戳的中间态,
// 由 internal/plan 汇流排序后交 builder 序列化。
package scenario
