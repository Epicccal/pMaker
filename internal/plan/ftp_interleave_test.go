package plan_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖跨流 start_after 的时间编排(两段式 scheduler),典型为 FTP 控制通道 ↔ 数据通道
// 的消息级双向交错:数据 flow start_after=控制流.150、控制流 226 start_after=数据流。
// 断言经 plan.Plan 汇流后各包 Time 的相对顺序(150 < data < 226),flow 层的 seq/ack 推导
// 与包序不含时间,由 flow_test.go 覆盖。

// planFlow 构造一条 open/close 均为 none 的 flow(便于在测试里精确定位时间),
// 整流 start_after=sa,若干消息。sport 区分多流同 Time 包。
func planFlow(name string, sport uint16, sa string, msgs ...scenario.Message) scenario.FlowSpec {
	return scenario.FlowSpec{
		Name: name, StartAfter: sa,
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: sport, DPort: 80, ClientISN: 100, ServerISN: 200}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "none", Close: "none"}},
		},
		Messages: msgs,
	}
}

// msg 构造一条带可选 message_id 与 message 级 start_after 的单字节 payload 消息。
func msg(from, id, sa string) scenario.Message {
	return scenario.Message{
		From: from, MessageID: id, StartAfter: sa,
		Stack: []scenario.Layer{{Type: "payload_hex",
			Fields: scenario.PayloadHex("0x" + hex.EncodeToString([]byte("x")))}},
	}
}

// TestFTPBidirectionalPlan 复现"Validate 过 / Plan 失败"的探针场景(见 plan.md 附录 A):
// 控制通道的末条消息(226)message 级 start_after: data(等数据通道整流结束),
// 数据通道 flow 级 start_after: control.pasv(150 收完后才开始)。整流粒度会死锁
// (互相等对方整流先完成),消息粒度两段式展开应打通它。
func TestFTPBidirectionalPlan(t *testing.T) {
	// control: retr → pasv(=150,被 data 引用) → 226(start_after data,等数据传完)
	control := planFlow("control", 1111, "",
		msg("src", "retr", ""),
		msg("dst", "pasv", ""),
		msg("dst", "", "data"),
	)
	// data: 整流 start_after control.pasv(150 收完后才开始)
	data := planFlow("data", 2222, "control.pasv", msg("src", "", ""))
	s := &scenario.Scenario{LinkType: "ethernet", Seed: 1,
		Flows: []scenario.FlowSpec{control, data}}

	if err := scenario.Validate(s); err != nil {
		t.Fatalf("Validate 应通过(方案A 已放行): %v", err)
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan 应成功(方案B 目标),实失败: %v", err)
	}
	t.Logf("Plan 成功,共 %d 包", len(planned))
	// 用 sport 区分两流:control=1111,data=2222。pasv 是 control 第 2 条消息的数据段
	// (sport=80,因为 from=dst 反转);226 是 control 第 3 条(from=dst,sport=80)。
	// data 的包 sport=2222 或 dport=2222。
	// 期望时序:control.pasv 的数据段 < data 首包 < control.226 的数据段。
	var pasvEnd, dataFirst, msg226 time.Time
	for _, pp := range planned {
		sp, dp := tcpPorts(pp)
		// control 的 dst->src 消息(pasv、226)数据段:sport=80(服务端发出),dport=1111。
		if sp == 80 && dp == 1111 {
			if pasvEnd.IsZero() {
				pasvEnd = pp.Time // 第一个 dst->src 数据段 = pasv
			}
			msg226 = pp.Time // 最后一个 dst->src 数据段 = 226
		}
		if sp == 2222 || dp == 2222 {
			if dataFirst.IsZero() || pp.Time.Before(dataFirst) {
				dataFirst = pp.Time
			}
		}
	}
	if pasvEnd.IsZero() || msg226.IsZero() || dataFirst.IsZero() {
		t.Fatalf("未定位到关键包: pasv=%v dataFirst=%v 226=%v", pasvEnd, dataFirst, msg226)
	}
	if !pasvEnd.Before(dataFirst) {
		t.Errorf("control.pasv(%v) 应早于 data 首包(%v)", pasvEnd, dataFirst)
	}
	if !dataFirst.Before(msg226) {
		t.Errorf("data 首包(%v) 应早于 control.226(%v)", dataFirst, msg226)
	}
}
