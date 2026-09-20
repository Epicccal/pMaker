package summary_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/summary"
)

// TestFormatPacketSummariesAlignsColumns: 多行输出必须跨行对齐——序号位数变化([1] vs [12])、
// IP 长度不一(10.0.0.1 vs 192.168.100.1 vs 无 IP 的 "-")不应让箭头列与协议栈列错位。
// 用列位置而非逐字符比对,直接断言"对齐"这一整表属性,避免脆弱的空格计数。
func TestFormatPacketSummariesAlignsColumns(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	// 12 包:序号达两位(idxW=2);混入长 IP 与无 IP 包,制造左/右 IP 宽度差。
	planned := make([]scenario.PlannedPacket, 12)
	for i := range planned {
		planned[i] = scenario.PlannedPacket{
			Packet: scenario.Packet{Stack: []scenario.Layer{
				{Type: "eth"},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp"},
			}},
			Time: base.Add(time.Duration(i) * time.Millisecond),
		}
	}
	planned[9].Packet.Stack[1] = scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.100.1", Dst: "192.168.100.80"}}
	planned[11].Packet.Stack = []scenario.Layer{{Type: "eth"}} // 无 IP → "- -> -"

	summaries := summary.SummarizeOut(planned, outOfPlanned(planned))
	lines := summary.FormatPacketSummaries(summaries)
	if len(lines) != len(planned) {
		t.Fatalf("行数=%d,期望 %d", len(lines), len(planned))
	}

	// 对齐不变量:每行的 ']'(序号尾)、箭头、协议栈起点三列在所有行落同一位置。
	// stack 右锚于行末,故其起点列 = len(line) - len(stack)。
	var closeCol, arrowCol, stackCol int
	for i, line := range lines {
		cClose := strings.Index(line, "]")
		cArrow := strings.Index(line, "->")
		if cArrow < 0 {
			cArrow = strings.Index(line, "<-")
		}
		cStack := len(line) - len(summaries[i].Stack)
		if i == 0 {
			closeCol, arrowCol, stackCol = cClose, cArrow, cStack
			continue
		}
		if cClose != closeCol {
			t.Errorf("第%d行 ']' 列=%d,首行=%d,序号未对齐", i+1, cClose, closeCol)
		}
		if cArrow != arrowCol {
			t.Errorf("第%d行箭头列=%d,首行=%d,箭头未对齐", i+1, cArrow, arrowCol)
		}
		if cStack != stackCol {
			t.Errorf("第%d行栈列=%d,首行=%d,协议栈未对齐", i+1, cStack, stackCol)
		}
	}

	// 序号本身在两位时应右对齐补空格(无 IP 行序号 12 不补,1 补为 " 1")。
	if lines[0][:4] != "[ 1]" {
		t.Errorf("首行序号=%q,期望 [ 1](两位宽右对齐)", lines[0][:4])
	}
	if lines[11][:4] != "[12]" {
		t.Errorf("末行序号=%q,期望 [12]", lines[11][:4])
	}
}
