package flow

import (
	"encoding/hex"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// tftp_transfer 宏展开:把一条宏消息降解成 DATA[1..n]/ACK[1..n] 若干条普通 tftp 消息。
// 展开后 flow/plan/builder/summary/golden 全部不感知宏的存在。
// TFTP 分块是应用层成帧(块号 + ACK 锁步),不是传输层切片,不能复用 segment。
//
// 展开规则:
//   - n = ceil(len/block_size);len 恰为 block_size 整数倍时 n+1(补 0 字节末块)；len == 0 时恰一个 0 字节块。
//   - 块号 1..n 递增,超过 65535 硬错;DATA 的 from 继承宏消息,ACK 取反。
//   - DATA 块全部用 data_hex(避免二进制问题)。
//   - 宏的 message_id / start_after / offset_time 分别挂在末尾 ACK / DATA[1] / DATA[1]。
//   - interval 作为 ACK 与后续 DATA 的 offset_time;nil 时留空走默认链式接续(1ms)。

// ExpandTFTPTransfers 对一批 flow 做宏展开,返回展开后的 flow 列表
// (浅拷贝 FlowSpec、替换 Messages;不含宏时原切片透传,零分配)。
// 在 plan.Plan 进入算时阶段之前调用。
func ExpandTFTPTransfers(flows []scenario.FlowSpec) ([]scenario.FlowSpec, error) {
	var out []scenario.FlowSpec
	for i, f := range flows {
		msgs, changed, err := expandTFTPTransfer(f.Messages)
		if err != nil {
			return nil, fmt.Errorf("flow[%d](%s): %w", i, f.Name, err)
		}
		if !changed {
			continue // 无宏,原 flow 透传
		}
		if out == nil {
			out = make([]scenario.FlowSpec, len(flows))
			copy(out, flows)
		}
		f.Messages = msgs
		out[i] = f
	}
	if out == nil {
		return flows, nil
	}
	return out, nil
}

// expandTFTPTransfer 把 messages 里所有 tftp_transfer 宏消息展开成普通 tftp 消息,
// 其余消息原样透传。changed 为 true 当且仅当至少发现并处理了一个宏,与展开后条数无关。
// 纯函数,无副作用。
func expandTFTPTransfer(msgs []scenario.Message) (out []scenario.Message, changed bool, err error) {
	for _, m := range msgs {
		if _, ok := transferMacroOf(m); ok {
			changed = true
			break
		}
	}
	if !changed {
		return msgs, false, nil // 快速路径:无宏,原样透传(零分配)
	}
	out = make([]scenario.Message, 0, len(msgs))
	for _, m := range msgs {
		if tf, ok := transferMacroOf(m); ok {
			sub, e := expandTransferMacro(tf, m)
			if e != nil {
				return nil, false, e
			}
			out = append(out, sub...)
			continue
		}
		out = append(out, m)
	}
	return out, true, nil
}

// transferMacroOf 判断一条消息是否恰为单个 tftp_transfer 宏
// (位置/字段合法性由 scenario.Validate 提前拦截,这里只识别不校验)。
func transferMacroOf(m scenario.Message) (*scenario.TFTPTransferFields, bool) {
	if len(m.Stack) != 1 {
		return nil, false
	}
	tf, ok := m.Stack[0].Fields.(*scenario.TFTPTransferFields)
	return tf, ok
}

// expandTransferMacro 展开一条宏消息:数据切块、块号分配、方向交替、
// message_id / offset_time 的挂点。
func expandTransferMacro(tf *scenario.TFTPTransferFields, m scenario.Message) ([]scenario.Message, error) {
	data, err := transferData(tf)
	if err != nil {
		return nil, err
	}
	bs := uint32(scenario.TFTPDefaultBlockSize)
	if tf.BlockSize != nil {
		bs = uint32(*tf.BlockSize)
	}
	if bs == 0 {
		return nil, fmt.Errorf("block_size 须 ≥ 1(校验阶段应已拦截)")
	}
	n := scenario.TFTPTransferBlockCount(uint32(len(data)), bs)
	if n > 65535 {
		return nil, fmt.Errorf("block_size %d 下需 %d 块,超过块号上限 65535(约 32 MB);请增大 block_size", bs, n)
	}

	peerFrom := "src"
	if m.From == "src" {
		peerFrom = "dst"
	}
	out := make([]scenario.Message, 0, n*2)
	for i := uint32(1); i <= n; i++ {
		block := uint16(i)
		// DATA[1] 携带宏自身的 offset_time / start_after;后续 DATA 与每条 ACK = interval。
		off, after := m.OffsetTime, m.StartAfter
		if i > 1 {
			off, after = tf.Interval, ""
		}
		out = append(out, tftpDATAMsg(data, i, bs, block, m.From, off, after))
		out = append(out, tftpACKMsg(block, peerFrom, tf.Interval, ""))
	}
	// message_id 挂在最后一条 ACK 上(整组完成语义,start_after 引用从这里起算)。
	out[len(out)-1].MessageID = m.MessageID
	return out, nil
}

// transferData 取宏的传输字节:data / data_hex 互斥由校验阶段保证。
func transferData(tf *scenario.TFTPTransferFields) ([]byte, error) {
	if tf.DataHex != "" {
		return scenario.ParsePayloadHex(tf.DataHex)
	}
	return []byte(tf.Data), nil
}

// tftpDATAMsg 造第 i 块的 DATA 消息;载荷用 data_hex 表达(0 字节块留空)。
// off/after 仅首块携带(宏自身的 offset_time / start_after)。
func tftpDATAMsg(data []byte, i, bs uint32, block uint16, from string, off *scenario.Offset, after string) scenario.Message {
	var chunk []byte
	if start := (i - 1) * bs; start < uint32(len(data)) {
		end := min(i*bs, uint32(len(data)))
		chunk = data[start:end]
	}
	var dataHex string
	if len(chunk) > 0 {
		dataHex = "0x" + hex.EncodeToString(chunk)
	}
	return scenario.Message{
		From:       from,
		OffsetTime: off,
		StartAfter: after,
		Stack: []scenario.Layer{{Type: "tftp", Fields: &scenario.TFTPFields{
			Opcode:  tftpOpcodeNode("data"),
			Block:   &block,
			DataHex: dataHex,
		}}},
	}
}

// tftpACKMsg 造对端回给第 block 块的 ACK 消息;id 非空时挂在消息上(调用方只给末尾 ACK)。
func tftpACKMsg(block uint16, from string, off *scenario.Offset, id string) scenario.Message {
	return scenario.Message{
		From:       from,
		OffsetTime: off,
		MessageID:  id,
		Stack: []scenario.Layer{{Type: "tftp", Fields: &scenario.TFTPFields{
			Opcode: tftpOpcodeNode("ack"),
			Block:  &block,
		}}},
	}
}

// tftpOpcodeNode 造字符串标量 yaml.Node,与 YAML 解码产物同形态
// (builder 的 serializeTFTP 经 scenario.ParseTFTPOpcode 吃这个)。
func tftpOpcodeNode(name string) yaml.Node {
	return yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}
}
