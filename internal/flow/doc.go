// Package flow 生成有状态的流量:TCP 三次握手、seq/ack 递推、时间戳编排。
//
// 所有随机(随机端口、IP ID、payload 填充)与时间戳均由可配置 seed 派生,
// 不使用全局 rand 或 time.Now(),以保证输出确定性可复现。
package flow
