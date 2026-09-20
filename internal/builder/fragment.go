package builder

import (
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// 本文件实现 ipv4/ipv6 的 mtu 自动分片。
//
// 分片 = 重新序列化,不是改字节:在反向序列化循环到达写了 mtu 的那层 IP 时,
// buf.Bytes() 恰是该层完整载荷(内层 L4 checksum 已基于完整数据报算好 —— 正是
// 分片要的正确值:各片共享的 L4 头校验和本就覆盖重组后的完整数据报)。抓一份
// 拷贝切块,逐片重建「外层原样 + 目标 IP 层(计数器 ID / MF / 偏移)+ Payload(块)」
// 再走同一套序列化 —— 外层 IP/UDP 的长度与 checksum 逐片自动重算,隧道嵌套免费正确。
//
// 实现不变式(违反即静默断链):
//   - 目标 IP 层必须是已构建层对象的字段快照复用,绝不按层名重走 buildIPv4/buildIPv6
//     —— 片栈在目标层之后只剩 payload,按层名重推导会落 TCP 惯例缺省(proto 恒 6);
//   - 分片器绝不回写 scenario Fields:flow 模板的 Fields 指针跨包共享,回写会把
//     计数器 ID 泄漏进同 flow 的后续展开包。ID 只写进分片器自建的层对象副本。

// fragTarget 是写了 mtu 的目标 IP 层(校验保证一个 stack 至多一层)。
type fragTarget struct {
	idx    int // serItems 中目标 IP 层的下标(与 add 顺序一致)
	family string
	mtu    int
	v4     *layers.IPv4 // family=ipv4 时非 nil(已构建层对象,只读快照来源)
	v6     *layers.IPv6 // family=ipv6 时非 nil
	// nextHeader 仅 ipv6 有意义:主头原 NextHeader,分片时移入 Fragment 扩展头。
	nextHeader layers.IPProtocol
}

// maxDatagramSize 返回目标层能承载的数据报上限:超了既写不进 16 位长度字段,
// 也超出片偏移 13 位(0x1FFF×8=65528)的寻址范围,切不出合法分片。
func maxDatagramSize(family string, headerLen int) int {
	if family == "ipv6" {
		return 65535 // IPv6 主头 payload_length 16 位;分片路径在目标层 SerializeTo 前截取,不走 Jumbo
	}
	return 65535 - headerLen // IPv4 total_length 含头,16 位
}

// cutBlocks 把载荷按 block(8 字节对齐)切块;末片取余,余数恰为 0 时末片是整块
// (此时总分片数 = len/blockSize,末片 MF=0,不产零长末片)。返回各块与对应的
// 字节偏移(8 字节对齐,除末片外块长必对齐)。
func cutBlocks(payload []byte, block int) (blocks [][]byte, offsets []int) {
	if len(payload) == 0 {
		return nil, nil
	}
	for off := 0; off < len(payload); {
		end := min(off+block, len(payload))
		b := make([]byte, end-off)
		copy(b, payload[off:end])
		blocks = append(blocks, b)
		offsets = append(offsets, off)
		off = end
	}
	return blocks, offsets
}

// fragmentFrames 为一个超限数据报生成逐片的 serItems(不含外层,外层由调用方拼)。
// 第 k 项对应第 k 片:目标 IP 层的片变体(计数器 ID / MF / 偏移;IPv6 另插 Fragment
// 扩展头)+ gopacket.Payload(块)。ID 消耗 buildContext 的确定性计数器:
// 同一数据报各片共用,只在真正分片时消耗一个值。
func fragmentFrames(ctx *buildContext, target *fragTarget, payload []byte) ([][]serItem, error) {
	var headerLen, blockSize int
	switch target.family {
	case "ipv4":
		headerLen = 20 + ipv4OptionSize(target.v4)
		blockSize = (target.mtu - headerLen) &^ 7
	case "ipv6":
		headerLen = 40 + 8 // 主头 + Fragment 扩展头
		blockSize = (target.mtu - 40 - 8) &^ 7
	}
	if blockSize <= 0 {
		return nil, fmt.Errorf("mtu=%d 减去头长 %d 后切不出载荷", target.mtu, headerLen)
	}
	blocks, offsets := cutBlocks(payload, blockSize)

	// 数据报过大无法分片:末片起始偏移最大 0x1FFF×8=65528,且 16 位长度字段装不下
	// 整个数据报。目标层载荷超限时在此硬错,同时兜住片偏移合法性(计数器切块的
	// offset 由该上限兜住,不存在越界片)。
	if limit := maxDatagramSize(target.family, headerLen); len(payload) > limit {
		return nil, fmt.Errorf("%s 数据报过大无法分片:载荷 %d 字节超过 %s 分片上限 %d 字节(片偏移 13 位 + 长度 16 位的硬边界);请减小载荷或调大 mtu", target.family, len(payload), target.family, limit)
	}

	// 确定性 ID:只在真正分片时消耗,同一数据报各片共用。
	ctx.ipID++
	id := ctx.ipID

	items := make([][]serItem, len(blocks))
	for k, blk := range blocks {
		boff := offsets[k]
		notLast := k < len(blocks)-1
		var frag []serItem
		if target.family == "ipv4" {
			ip4 := *target.v4 // 字段快照副本:改写 Id/Flags/FragOffset,不动原层对象
			ip4.Id = uint16(id)
			ip4.Flags = 0
			if notLast {
				ip4.Flags = layers.IPv4MoreFragments
			}
			ip4.FragOffset = uint16(boff / 8) // gopacket 的 FragOffset 以 8 字节为单位
			frag = append(frag, serItem{layer: &ip4, opts: defaultSerOpts})
		} else {
			ip6 := *target.v6 // 主头 NextHeader 改 44,原值移入 Fragment 扩展头
			ip6.NextHeader = layers.IPProtocolIPv6Fragment
			frag = append(frag, serItem{layer: &ip6, opts: defaultSerOpts})
			frag = append(frag, serItem{layer: &layers.IPv6Fragment{
				NextHeader:     target.nextHeader,
				FragmentOffset: uint16(boff / 8),
				MoreFragments:  notLast,
				Identification: id,
			}, opts: defaultSerOpts})
		}
		// 载荷固定是原始块:L4 头(含基于完整数据报算好的 checksum)在块内原样携带,
		// 各片不再有独立 L4 层 —— 解码端重组后才能看到 L4,gopacket 回读只到 Fragment 层。
		frag = append(frag, serItem{layer: gopacket.Payload(blk), opts: defaultSerOpts})
		items[k] = frag
	}
	return items, nil
}
