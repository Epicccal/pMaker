// Package flow 将有状态 TCP 会话脚本展开为带显式时间戳的 PlannedPacket。
//
// 当前实现负责三次握手、seq/ack 递推、按 segment.mss 分段应用层消息,
// 以及 fin/rst 关闭序列,并自管流内时间轴(锚点由 plan 传入)。
//
// 时间语义为「相对上一条消息 + 跨流独立」:
//   - 跨流独立由 plan 保证:每条 flow 的 anchor=base+flow.offset_time(无 offset 则 = base),
//     互不依赖、可并行;flow 内部不推导跨流接续。
//   - 流内链式:单游标 msgCursor(= 上一条消息末尾),每条消息 start = msgCursor + offset
//     (无 offset 则紧接 msgCursor);第一条消息的"上一条"= 握手完成后(msgAnchor)。
//     offset>=0 天然单调,无需夹紧;慢响应拖慢下一条请求(正常非流水线 HTTP)。
//
// 详见 Expand 的文档注释。
package flow
