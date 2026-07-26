package scenario

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Scenario 是一个场景文件的顶层结构。
type Scenario struct {
	LinkType string     `yaml:"link_type"`
	Seed     int64      `yaml:"seed"`
	BaseTime *AbsTime   `yaml:"base_time"` // 全局基准时刻(绝对 ISO8601);缺省=确定性 2020 基准(见 internal/plan)
	Packets  []Packet   `yaml:"packets"`
	Flows    []FlowSpec `yaml:"flows"`
}

// FlowSpec 是一条有状态会话;展开器把它降解成一串 Packet(见 internal/flow)。
// flow.stack 中的 src 表示 TCP SYN 发起方,dst 表示 SYN 接收方。
type FlowSpec struct {
	Name       string  `yaml:"name"`
	OffsetTime *Offset `yaml:"offset_time"` // 流锚 = base_time + offset_time;缺省=base(跨流独立、并发,不接续别的 flow)
	// StartAfter 可选,形如 "flow名"(该 flow 整流结束,挥手后)或 "flow名.message_id"
	// (该消息整组完成,msgCursor);置则本 flow 的锚 = 被引时刻 + offset_time(缺省 0 紧接),
	// 实现"一个 flow 在另一个 flow / 另一个 flow 某消息完成后开始"(如 FTP 控制通道触发数据通道)。
	// 见 internal/plan 的多遍拓扑编排。
	StartAfter string    `yaml:"start_after"`
	Stack      []Layer   `yaml:"stack"`
	Messages   []Message `yaml:"messages"`
}

// Message 是一条方向性的应用层消息;当前只支持一个 payload 生产层。
type Message struct {
	From    string   `yaml:"from"` // src | dst
	Stack   []Layer  `yaml:"stack"`
	Segment *Segment `yaml:"segment"`
	// OffsetTime 是本消息起始相对上一条消息末尾的时长偏移:缺省紧接上一条末尾,
	// 带 offset 则 = 上一条末尾 + offset。第一条消息的"上一条"= 握手完成后
	// (无握手则 = 流锚 anchor)。用于多轮请求间的间隔。
	OffsetTime *Offset `yaml:"offset_time"`
	// MessageID 是本消息的可选标识;供其它 flow 的 start_after 引用本消息整组完成
	// 时刻(msgCursor)。同一 flow 内必须唯一;不设则不被引用。见 internal/plan。
	MessageID string `yaml:"message_id"`
	// StartAfter 可选,形如 "flow名"(该 flow 整流结束,挥手后)或 "flow名.message_id"
	// (该消息整组完成,msgCursor);置则本消息起点 = 被引时刻 + offset_time(缺省 0 紧接),
	// 实现"某条消息在另一个 flow / 另一个 flow 某消息完成后才开始"(如控制通道触发本流
	// 某条迟到请求)。禁止引用本 flow(同流自引);流内顺序由 message 链式游标保证。
	// 见 internal/plan 的多遍拓扑编排与 internal/flow 的 resolve 回调。
	StartAfter string `yaml:"start_after"`
}

// Segment 是消息的分段策略。MSS 为实际切段大小(0=不切,整条一段)。
type Segment struct {
	MSS int `yaml:"mss"`
	// Interval 是同一消息各数据段之间的时间间隔;缺省=1ms(与未显式定时的历史行为逐字节等价)。
	// 显式给出(如 +10ms)用于模拟慢速分段/RTT。只作用于数据段;对端 ACK 用 DefaultStep,
	// 不被数据段节奏传染(保持"只让数据慢"的语义纯净)。
	Interval *Offset `yaml:"interval"`
}

// Packet 是一个数据包:name 可选 + 由外到内的有序 layer 栈。
type Packet struct {
	Name          string   `yaml:"name"`
	OffsetTime    *Offset  `yaml:"offset_time"` // 该包时刻 = 上一包 + offset(第一包 = base_time+offset);缺省=接续默认游标(+1ms)
	Stack         []Layer  `yaml:"stack"`
	SummaryLayers []string `yaml:"-"` // flow 展开后保留应用层协议语义,仅用于 CLI 摘要
}

// PlannedPacket 是 scenario 模型 + 显式时间戳的中间态:
// standalone packets 与 flows 展开后的包在 internal/plan 汇流成 PlannedPacket 列表,
// 按 Time 排序后再交给 builder 序列化。内嵌 Packet 以复用 Name/Stack/SummaryLayers
// 与 quote_from 命名查找、摘要展示等既有逻辑。
type PlannedPacket struct {
	Packet
	Time time.Time
}

// Layer 是层栈中的一层:类型名 + 已按类型解码的字段结构(见各 *Fields)。
type Layer struct {
	Type   string
	Fields any
}

// Hex 接受十进制整数或 "0x88a8" 形式的十六进制字符串。
type Hex uint32

// UnmarshalYAML 允许 ethertype/tpid/type/checksum 等字段用 0x.. 或十进制书写。
func (h *Hex) UnmarshalYAML(node *yaml.Node) error {
	var i int64
	if err := node.Decode(&i); err == nil {
		*h = Hex(i)
		return nil
	}
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return fmt.Errorf("非法十六进制 %q", s)
	}
	*h = Hex(v)
	return nil
}

// ParsePayloadHex 解析 0x 前缀的十六进制字符串。
func ParsePayloadHex(s string) ([]byte, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return nil, fmt.Errorf("payload_hex 需要 0x 前缀,例如 0xdeadbeef")
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s) == 0 {
		return nil, fmt.Errorf("payload_hex 不能为空")
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("payload_hex 需要偶数个十六进制字符")
	}
	return hex.DecodeString(s)
}
