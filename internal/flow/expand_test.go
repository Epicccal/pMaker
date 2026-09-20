package flow

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// tftp_transfer 宏展开的表驱动测试。
// 展开规则见 expand.go 头注释;端到端链路(Validate → plan → golden)见 internal/golden。

// macroStack 造单层 tftp_transfer 宏消息的 stack。
func macroStack(data, dataHex string, bs *uint16) []scenario.Layer {
	return []scenario.Layer{{Type: "tftp_transfer", Fields: &scenario.TFTPTransferFields{
		Data: data, DataHex: dataHex, BlockSize: bs,
	}}}
}

// tftpOf 取展开消息里的 tftp 字段。
func tftpOf(t *testing.T, m scenario.Message) *scenario.TFTPFields {
	t.Helper()
	if len(m.Stack) != 1 {
		t.Fatalf("展开产物须单层,得到 %d 层", len(m.Stack))
	}
	f, ok := m.Stack[0].Fields.(*scenario.TFTPFields)
	if !ok {
		t.Fatalf("展开产物应为 tftp 层,得到 %T", m.Stack[0].Fields)
	}
	return f
}

// TestExpandTransferChunking 切块与块号:整除补空末块 / 非整除 / 空数据。
func TestExpandTransferChunking(t *testing.T) {
	bs2 := uint16(2)
	tests := []struct {
		name  string
		data  string
		bs    *uint16
		want  []string // 每块的 data_hex 期望(0 字节块 = 空串)
		total int      // 展开后的消息总数
	}{
		{
			name:  "exact multiple appends empty final block",
			data:  "AB",
			bs:    &bs2,
			want:  []string{"0x4142", ""},
			total: 4, // DATA1 ACK1 DATA2 ACK2
		},
		{
			name:  "partial final block",
			data:  "ABC",
			bs:    &bs2,
			want:  []string{"0x4142", "0x43"},
			total: 4,
		},
		{
			name:  "empty data single empty block",
			data:  "",
			bs:    nil, // 缺省 512
			want:  []string{""},
			total: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs := []scenario.Message{{From: "src", Stack: macroStack(tt.data, "", tt.bs)}}
			got, _, err := expandTFTPTransfer(msgs)
			if err != nil {
				t.Fatalf("expand: %v", err)
			}
			if len(got) != tt.total {
				t.Fatalf("展开后 %d 条消息, want %d", len(got), tt.total)
			}
			for i, want := range tt.want {
				f := tftpOf(t, got[i*2]) // 偶数位 = DATA,奇数位 = ACK
				op := 3
				if gotOpcode, _ := scenario.ParseTFTPOpcode(f.Opcode); gotOpcode != uint16(op) {
					t.Fatalf("第 %d 块 opcode = %d", i, gotOpcode)
				}
				if f.Block == nil || *f.Block != uint16(i+1) {
					t.Fatalf("第 %d 块 block = %v, want %d", i+1, f.Block, i+1)
				}
				if f.DataHex != want {
					t.Fatalf("块 %d data_hex = %q, want %q", i+1, f.DataHex, want)
				}
				if f.Data != "" {
					t.Fatalf("展开产物须用 data_hex,得到 data=%q", f.Data)
				}
			}
			// 奇数位须是 ACK,块号与前面的 DATA 对齐。
			for i := 0; i*2+1 < len(got); i++ {
				f := tftpOf(t, got[i*2+1])
				if op, _ := scenario.ParseTFTPOpcode(f.Opcode); op != 4 {
					t.Fatalf("第 %d 条应为 ACK,得到 opcode %d", i*2+1, op)
				}
			}
		})
	}
}

// TestExpandTransferDirections 方向:DATA 继承宏的 from,ACK 取反。
func TestExpandTransferDirections(t *testing.T) {
	for _, from := range []string{"src", "dst"} {
		msgs := []scenario.Message{{From: from, Stack: macroStack("ab", "", nil)}}
		got, _, err := expandTFTPTransfer(msgs)
		if err != nil {
			t.Fatalf("expand: %v", err)
		}
		if got[0].From != from {
			t.Fatalf("DATA from = %q, want %q", got[0].From, from)
		}
		peer := "dst"
		if from == "dst" {
			peer = "src"
		}
		if got[1].From != peer {
			t.Fatalf("ACK from = %q, want %q", got[1].From, peer)
		}
	}
}

// TestExpandTransferMessageID message_id 挂在最后一条 ACK 上。
func TestExpandTransferMessageID(t *testing.T) {
	msgs := []scenario.Message{{From: "src", MessageID: "xfer", Stack: macroStack("AB", "", nil)}}
	got, _, err := expandTFTPTransfer(msgs)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	for i, m := range got {
		want := ""
		if i == len(got)-1 {
			want = "xfer"
		}
		if m.MessageID != want {
			t.Fatalf("消息 %d 的 message_id = %q, want %q", i, m.MessageID, want)
		}
	}
}

// offsetOf 从字符串构造 *scenario.Offset(字段不导出,走 UnmarshalYAML)。
func offsetOf(t *testing.T, s string) *scenario.Offset {
	t.Helper()
	o := &scenario.Offset{}
	node := yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
	if err := o.UnmarshalYAML(&node); err != nil {
		t.Fatalf("构造 offset %q: %v", s, err)
	}
	return o
}

// TestExpandTransferTimingAttachment 时间挂点:DATA[1] 带宏自身的 offset_time /
// start_after,后续 DATA 与每条 ACK 只带 interval(不带 start_after)。
// 锁住「后续 DATA 误带宏 start_after 导致同刻」「后续 DATA 丢 interval」两类回归。
func TestExpandTransferTimingAttachment(t *testing.T) {
	bs2 := uint16(2)
	iv := offsetOf(t, "2ms")
	off := offsetOf(t, "5ms")
	macro := []scenario.Layer{{Type: "tftp_transfer", Fields: &scenario.TFTPTransferFields{
		DataHex: "0x41424344", BlockSize: &bs2, Interval: iv,
	}}}
	msgs := []scenario.Message{{From: "src", OffsetTime: off, StartAfter: "req.rrq", Stack: macro}} // 4 字节 = 2 块整数倍,补空末块
	got, _, err := expandTFTPTransfer(msgs)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(got) != 6 { // DATA1 ACK1 DATA2 ACK2 DATA3 ACK3
		t.Fatalf("展开后 %d 条消息, want 6", len(got))
	}
	for i, m := range got {
		wantOff, wantAfter := iv, ""
		switch {
		case i == 0: // DATA[1] 唯一携带宏自身的挂点
			wantOff, wantAfter = off, "req.rrq"
		case i%2 == 1: // ACK 带 interval
		default: // 后续 DATA 也带 interval(修复前误带宏自身 offset_time)
		}
		if m.OffsetTime == nil || m.OffsetTime.Duration() != wantOff.Duration() {
			t.Fatalf("消息 %d offset_time = %v, want %v", i, m.OffsetTime, wantOff)
		}
		if m.StartAfter != wantAfter {
			t.Fatalf("消息 %d start_after = %q, want %q", i, m.StartAfter, wantAfter)
		}
	}
	// 宏 interval 未写(nil)时:后续 DATA 与 ACK 均不带 offset_time,走默认链式接续。
	got2, _, err := expandTFTPTransfer([]scenario.Message{{From: "src", Stack: macroStack("AB", "", &bs2)}})
	if err != nil {
		t.Fatalf("expand(no interval): %v", err)
	}
	for i, m := range got2 {
		if m.OffsetTime != nil {
			t.Fatalf("无 interval 时消息 %d 不应带 offset_time,得到 %v", i, m.OffsetTime)
		}
		if m.StartAfter != "" {
			t.Fatalf("无 interval 时消息 %d 不应带 start_after: %q", i, m.StartAfter)
		}
	}
}

// TestExpandTransferOversize 块数超 65535 硬错。
func TestExpandTransferOversize(t *testing.T) {
	big := make([]byte, 512*65535+1) // 65536 块
	msgs := []scenario.Message{{From: "src", Stack: macroStack(string(big), "", nil)}}
	if _, _, err := expandTFTPTransfer(msgs); err == nil {
		t.Fatal("块数超过 65535 应报错")
	}
}
