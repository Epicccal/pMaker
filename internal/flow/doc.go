// Package flow 将有状态 TCP 会话脚本展开为有序 stack 包(不含时间戳)。
//
// 当前实现负责三次握手、seq/ack 递推、按 segment.mss 分段应用层消息,
// 以及 fin/rst 关闭序列。时间戳由 internal/plan 在汇流阶段统一分配
// (默认 base+i*ms,或按 flow.start / base_time 显式编排),flow 本身只产出 stack 包。
package flow
