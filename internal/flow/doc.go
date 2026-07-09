// Package flow 将有状态 TCP 会话脚本展开为有序 stack 包。
//
// 当前实现负责三次握手、seq/ack 递推、按 segment.mss 分段应用层消息,
// 以及 fin/rst 关闭序列;时间戳由 builder/writer 链路在后续阶段处理。
package flow
