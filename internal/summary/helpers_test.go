package summary_test

import (
	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// outOfPlanned 把 planned 一一映射为未分片的 OutPacket,供单测以 SummarizeOut 的
// 真实入参形态驱动(与生产链路同函数):这些测试只关心方向归一化与端点展示,
// 不经 builder 序列化,Data 留空即可(SummarizeOut 只读 Frag 与 Time)。
func outOfPlanned(planned []scenario.PlannedPacket) []builder.OutPacket {
	pkts := make([]builder.OutPacket, len(planned))
	for i, pp := range planned {
		pkts[i] = builder.OutPacket{Time: pp.Time, Frag: builder.FragInfo{PlannedIdx: i, K: 0, N: 1}}
	}
	return pkts
}
