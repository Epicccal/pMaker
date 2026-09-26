package scenario_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// writeScenario 把 yaml 写进临时文件并返回路径,供 scenario.Load 走完整解析路径。
func writeScenario(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// TestLoadRejectsUnknownSegmentFields 验证 segment 的未实现字段(order/overlap/retransmit)
// 在解析层被拒,并带字段名。
//
// 覆盖 scenario.go 的 Load(KnownFields)与 validateLayer 路径。
func TestLoadRejectsUnknownSegmentFields(t *testing.T) {
	path := writeScenario(t, "seg.yaml", `link_type: ethernet
flows:
  - name: f
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        segment: { mss: 8, order: shuffled, overlap: 4, retransmit: [1] }
        stack:
          - payload_hex: "0xdeadbeef"
`)
	_, err := scenario.Load(path)
	if err == nil {
		t.Fatal("期望 Load 拒绝未实现的 segment 字段(order/overlap/retransmit),实际通过")
	}
	// 报错应点名至少一个未实现字段,且带文件路径包装。
	for _, want := range []string{"order", "overlap", "retransmit"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息应包含字段 %q,得到: %v", want, err)
		}
	}
}

// TestLoadRejectsTypoLayerField 验证 layer 内子字段(如 eth.scr 拼写错误)也被解析层拒绝,
// 并带字段名。覆盖 decodeKnownFields 对 layer 子树的校验。
func TestLoadRejectsTypoLayerField(t *testing.T) {
	path := writeScenario(t, "typo.yaml", `link_type: ethernet
packets:
  - stack:
      - eth:  { scr: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:  { sport: 1234, dport: 80, flags: [SYN] }
`)
	_, err := scenario.Load(path)
	if err == nil {
		t.Fatal("期望 Load 拒绝拼错字段 eth.scr,实际通过")
	}
	if !strings.Contains(err.Error(), "scr") {
		t.Errorf("错误信息应点名拼错字段 scr,得到: %v", err)
	}
}

// TestGREFieldsStrictDecode 验证 GRE 层的严格解码:登记字段被接受,未登记字段
// (如 gre: { foo: 1 })仍被拒 —— fieldsDecoder 泛型自动跟随 GREFields 结构体变化。
func TestGREFieldsStrictDecode(t *testing.T) {
	path := writeScenario(t, "gre-ok.yaml", `link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - gre:  { key: 0x1234 }
      - ipv4: { src: "192.168.1.1", dst: "192.168.1.2" }
      - tcp:  { sport: 1234, dport: 80, flags: [SYN] }
`)
	if _, err := scenario.Load(path); err != nil {
		t.Fatalf("登记字段 key 应被接受,实际报错: %v", err)
	}

	bad := writeScenario(t, "gre-bad.yaml", `link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - gre:  { foo: 1 }
      - ipv4: { src: "192.168.1.1", dst: "192.168.1.2" }
      - tcp:  { sport: 1234, dport: 80, flags: [SYN] }
`)
	_, err := scenario.Load(bad)
	if err == nil {
		t.Fatal("期望 Load 拒绝 gre 层未知字段 foo,实际通过")
	}
	if !strings.Contains(err.Error(), "foo") {
		t.Errorf("错误信息应点名未知字段 foo,得到: %v", err)
	}
}

// TestLoadAcceptsValidScenario 回归保护:合法场景不被未知字段校验误伤。
//
// 覆盖 scenario.go 的 Load + Validate 全路径。
func TestLoadAcceptsValidScenario(t *testing.T) {
	path := writeScenario(t, "ok.yaml", `link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:  { sport: 1234, dport: 80, flags: [SYN] }
`)
	if _, err := scenario.Load(path); err != nil {
		t.Fatalf("合法场景应通过 KnownFields 校验,实际失败: %v", err)
	}
}

// TestValidateQuoteFromReference 校验 Validate 拦截 quote_from 引用未知 packet。
func TestValidateQuoteFromReference(t *testing.T) {
	s := &scenario.Scenario{Packets: []scenario.Packet{{
		Stack: []scenario.Layer{{Type: "icmp", Fields: &scenario.ICMPFields{QuoteFrom: "missing"}}},
	}}}
	err := scenario.Validate(s)
	if err == nil || !strings.Contains(err.Error(), `quote_from 引用未知 packet "missing"`) {
		t.Fatalf("Validate() error=%v,期望 quote_from 未知引用", err)
	}
}

// TestValidateSegmentIntervalNeedsMSS: segment.interval 必须配 mss>0,否则整条不切、
// interval 无处生效,会被静默吞掉。validate 应尽早报错。
func TestValidateSegmentIntervalNeedsMSS(t *testing.T) {
	stack := []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80}},
		{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "none", Close: "none"}},
	}
	// 包内测试可直接构造 Offset(校验只看 Interval 指针非 nil,不看 Duration 值)。
	interval := &scenario.Offset{}
	msg := func(seg *scenario.Segment) scenario.Message {
		return scenario.Message{From: "src", Stack: []scenario.Layer{{Type: "payload_hex", Fields: scenario.PayloadHex("0xab")}}, Segment: seg}
	}

	// interval 无 mss → 报错。
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{{Name: "f", Stack: stack, Messages: []scenario.Message{
		msg(&scenario.Segment{Interval: interval}), // mss=0
	}}}}
	if err := scenario.Validate(s); err == nil || !strings.Contains(err.Error(), "interval 需配合 mss>0") {
		t.Fatalf("Validate() error=%v,期望 interval 需配合 mss>0", err)
	}

	// interval + mss>0 → 通过。
	s2 := &scenario.Scenario{Flows: []scenario.FlowSpec{{Name: "f", Stack: stack, Messages: []scenario.Message{
		msg(&scenario.Segment{MSS: 8, Interval: interval}),
	}}}}
	if err := scenario.Validate(s2); err != nil {
		t.Fatalf("Validate() 有 mss 时不应报错,得到 %v", err)
	}

	// 只 mss 无 interval → 通过。
	s3 := &scenario.Scenario{Flows: []scenario.FlowSpec{{Name: "f", Stack: stack, Messages: []scenario.Message{
		msg(&scenario.Segment{MSS: 8}),
	}}}}
	if err := scenario.Validate(s3); err != nil {
		t.Fatalf("Validate() 只 mss 不应报错,得到 %v", err)
	}
}

// loadValid 走 Load + Validate 全路径(语义校验在 Validate,不在 Load/KnownFields)。
func loadValid(t *testing.T, name, body string) *scenario.Scenario {
	t.Helper()
	path := writeScenario(t, name, body)
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("Load %s 失败: %v", name, err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("Validate %s 失败: %v", name, err)
	}
	return s
}

const flowStackYAML = `      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
`

// TestValidateRejectsDuplicateMessageID 验证同一 flow 内 message_id 重复被 Validate 拒,
// 并带字段名 + id 值。
func TestValidateRejectsDuplicateMessageID(t *testing.T) {
	path := writeScenario(t, "dupmsgid.yaml", "link_type: ethernet\nflows:\n  - name: f\n    stack:\n"+flowStackYAML+`    messages:
      - from: src
        message_id: dup
        stack:
          - payload: { payload: "aaaa" }
      - from: dst
        message_id: dup
        stack:
          - payload: { payload: "bbbb" }
`)
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	err = scenario.Validate(s)
	if err == nil {
		t.Fatal("期望 Validate 拒绝同一 flow 内重复 message_id,实际通过")
	}
	for _, want := range []string{"message_id", "dup", "重复"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息应包含 %q,得到: %v", want, err)
		}
	}
}

// TestValidateAcceptsMessageID 验证 message_id 可选、不设与唯一设置都通过 Validate。
func TestValidateAcceptsMessageID(t *testing.T) {
	loadValid(t, "okmsgid.yaml", "link_type: ethernet\nflows:\n  - name: f\n    stack:\n"+flowStackYAML+`    messages:
      - from: src
        message_id: first
        stack:
          - payload: { payload: "aaaa" }
      - from: dst
        message_id: second
        stack:
          - payload: { payload: "bbbb" }
      - from: src
        stack:
          - payload: { payload: "cccc" }
`)
}

// startAfterScenario 用模板 + 给定的两条 flow YAML 段拼一个场景,供 start_after 校验测试。
func startAfterScenario(flowsYAML string) string {
	return "link_type: ethernet\nflows:\n" + flowsYAML
}

// twoFlowYAML 生成两条 flow:第一条(name=control)的 dst 消息带 message_id: pasv;
// 第二条(name=data)的 start_after 由参数给出。用于各种 start_after 引用校验。
func twoFlowYAML(startAfter string) string {
	return "  - name: control\n    stack:\n" + flowStackYAML + `    messages:
      - from: src
        stack:
          - payload: { payload: "PASV" }
      - from: dst
        message_id: pasv
        stack:
          - payload: { payload: "227" }
  - name: data
    start_after: "` + startAfter + `"
    stack:
` + flowStackYAML + `    messages:
      - from: src
        stack:
          - payload: { payload: "data" }
`
}

// loadValidateErr 走 Load + Validate,返回 error(nil 表示通过)。
func loadValidateErr(t *testing.T, name, body string) error {
	t.Helper()
	path := writeScenario(t, name, body)
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("Load %s 失败(应可解析): %v", name, err)
	}
	return scenario.Validate(s)
}

func TestStartAfterAcceptsValid(t *testing.T) {
	if err := loadValidateErr(t, "ok.yaml", startAfterScenario(twoFlowYAML("control.pasv"))); err != nil {
		t.Fatalf("合法 start_after 应通过 Validate: %v", err)
	}
}

func TestStartAfterRejectsMalformed(t *testing.T) {
	err := loadValidateErr(t, "bad.yaml", startAfterScenario(twoFlowYAML("noformat")))
	if err == nil {
		t.Fatal("期望 Validate 拒绝格式错误的 start_after,实际通过")
	}
	for _, want := range []string{"start_after", "未知 flow"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误应包含 %q,得到: %v", want, err)
		}
	}
}

func TestStartAfterRejectsUnknownFlow(t *testing.T) {
	err := loadValidateErr(t, "noflow.yaml", startAfterScenario(twoFlowYAML("ghost.pasv")))
	if err == nil {
		t.Fatal("期望 Validate 拒绝引用未知 flow 的 start_after,实际通过")
	}
	for _, want := range []string{"未知 flow", "ghost"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误应包含 %q,得到: %v", want, err)
		}
	}
}

func TestStartAfterRejectsUnknownMessage(t *testing.T) {
	err := loadValidateErr(t, "nomsg.yaml", startAfterScenario(twoFlowYAML("control.ghost")))
	if err == nil {
		t.Fatal("期望 Validate 拒绝引用未知 message_id 的 start_after,实际通过")
	}
	for _, want := range []string{"未知 message_id", "ghost"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误应包含 %q,得到: %v", want, err)
		}
	}
}

func TestStartAfterRejectsSelfReference(t *testing.T) {
	// flow a 既被自引,又含 message_id pasv(故引用存在),但构成自环。
	body := "link_type: ethernet\nflows:\n  - name: a\n    start_after: \"a.pasv\"\n    stack:\n" + flowStackYAML + `    messages:
      - from: dst
        message_id: pasv
        stack:
          - payload: { payload: "x" }
`
	err := loadValidateErr(t, "self.yaml", body)
	if err == nil {
		t.Fatal("期望 Validate 拒绝 start_after 自引,实际通过")
	}
	if !strings.Contains(err.Error(), "循环依赖") {
		t.Errorf("错误应提及循环依赖,得到: %v", err)
	}
}

func TestStartAfterRejectsCycle(t *testing.T) {
	// a.pasv 存在,b.pasv 存在;a 引 b.pasv,b 引 a.pasv → 2-环。
	flowA := "  - name: a\n    start_after: \"b.pasv\"\n    stack:\n" + flowStackYAML + `    messages:
      - from: dst
        message_id: pasv
        stack:
          - payload: { payload: "x" }
`
	flowB := "  - name: b\n    start_after: \"a.pasv\"\n    stack:\n" + flowStackYAML + `    messages:
      - from: dst
        message_id: pasv
        stack:
          - payload: { payload: "y" }
`
	err := loadValidateErr(t, "cycle.yaml", "link_type: ethernet\nflows:\n"+flowA+flowB)
	if err == nil {
		t.Fatal("期望 Validate 拒绝 start_after 2-环,实际通过")
	}
	if !strings.Contains(err.Error(), "循环依赖") {
		t.Errorf("错误应提及循环依赖,得到: %v", err)
	}
}

func TestValidateRejectsDuplicateFlowName(t *testing.T) {
	flowA := "  - name: dup\n    stack:\n" + flowStackYAML + `    messages:
      - from: src
        stack:
          - payload: { payload: "a" }
`
	err := loadValidateErr(t, "dupname.yaml", "link_type: ethernet\nflows:\n"+flowA+flowA)
	if err == nil {
		t.Fatal("期望 Validate 拒绝重复 flow 名,实际通过")
	}
	for _, want := range []string{"dup", "不唯一"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误应包含 %q,得到: %v", want, err)
		}
	}
}

// TestStartAfterMessageLevel 校验 message 级 start_after:合法引用另一 flow 的 message_id 通过。
func TestStartAfterMessageLevel(t *testing.T) {
	body := "link_type: ethernet\nflows:\n" +
		"  - name: a\n    stack:\n" + flowStackYAML + `    messages:
      - from: src
        message_id: trig
        stack:
          - payload: { payload: "x" }
` +
		"  - name: b\n    stack:\n" + flowStackYAML + `    messages:
      - from: src
        stack:
          - payload: { payload: "y" }
      - from: src
        start_after: "a.trig"
        stack:
          - payload: { payload: "z" }
`
	if err := loadValidateErr(t, "msgok.yaml", body); err != nil {
		t.Fatalf("合法 message 级 start_after 应通过: %v", err)
	}
}

// TestStartAfterMessageLevelFlowRef:裸 flow 名引用(整流结束)应通过。
func TestStartAfterMessageLevelFlowRef(t *testing.T) {
	body := "link_type: ethernet\nflows:\n" +
		"  - name: a\n    stack:\n" + flowStackYAML + `    messages:
      - from: src
        stack:
          - payload: { payload: "x" }
` +
		"  - name: b\n    stack:\n" + flowStackYAML + `    messages:
      - from: src
        start_after: "a"
        stack:
          - payload: { payload: "z" }
`
	if err := loadValidateErr(t, "msgflow.yaml", body); err != nil {
		t.Fatalf("合法 message 级 start_after(裸 flow 名)应通过: %v", err)
	}
}

// TestStartAfterMessageLevelSameFlowRejected:message 级 start_after 同流自引应被拒。
func TestStartAfterMessageLevelSameFlowRejected(t *testing.T) {
	body := "link_type: ethernet\nflows:\n  - name: a\n    stack:\n" + flowStackYAML + `    messages:
      - from: src
        message_id: trig
        stack:
          - payload: { payload: "x" }
      - from: src
        start_after: "a.trig"
        stack:
          - payload: { payload: "z" }
`
	err := loadValidateErr(t, "msgself.yaml", body)
	if err == nil {
		t.Fatal("期望 Validate 拒绝 message 级 start_after 同流自引,实际通过")
	}
	if !strings.Contains(err.Error(), "禁止引用本 flow") {
		t.Errorf("错误应提及禁止引用本 flow,得到: %v", err)
	}
}

// TestStartAfterMessageLevelUnknownFlow:message 级引用未知 flow 应被拒。
func TestStartAfterMessageLevelUnknownFlow(t *testing.T) {
	body := "link_type: ethernet\nflows:\n" +
		"  - name: a\n    stack:\n" + flowStackYAML + `    messages:
      - from: src
        start_after: "ghost.pasv"
        stack:
          - payload: { payload: "x" }
`
	err := loadValidateErr(t, "msgnoflow.yaml", body)
	if err == nil {
		t.Fatal("期望 Validate 拒绝 message 级 start_after 引用未知 flow,实际通过")
	}
	if !strings.Contains(err.Error(), "未知 flow") {
		t.Errorf("错误应提及未知 flow,得到: %v", err)
	}
}

// TestStartAfterAcceptsFTPStyleInterleave 验证事件粒度循环检测放行 FTP 式合法交错:
// control.dataStart(=data 流锚) 依赖 control.150(消息级);
// control.226 依赖 data 流整流结束(消息级 start_after "data",data 整流完后才发 226)。
// flow 粒度会把 control→data 与 data→control 压成 2-环而误拦;事件粒度下两条跨流边
// 分别落在 control.150↔data.flowStart 与 control.226↔data.flowEnd,中间隔着流内链
// control.150→control.226,方向一致、不成环。
func TestStartAfterAcceptsFTPStyleInterleave(t *testing.T) {
	// control: 发 RETR(带 id:retr)、收 150(带 id:pasv)、收 226(start_after data,等数据通道整流结束)。
	control := "  - name: control\n    stack:\n" + flowStackYAML + `    messages:
      - from: src
        message_id: retr
        stack:
          - payload: { payload: "RETR x\r\n" }
      - from: dst
        message_id: pasv
        stack:
          - payload: { payload: "150\r\n" }
      - from: dst
        start_after: "data"
        stack:
          - payload: { payload: "226\r\n" }
`
	// data: 整流 start_after control.pasv(150 收完后才开始)。
	data := "  - name: data\n    start_after: \"control.pasv\"\n    stack:\n" + flowStackYAML + `    messages:
      - from: src
        stack:
          - payload: { payload: "file-bytes\r\n" }
`
	err := loadValidateErr(t, "interleave.yaml", "link_type: ethernet\nflows:\n"+control+data)
	if err != nil {
		t.Fatalf("FTP 式合法交错应通过 Validate: %v", err)
	}
}

// TestValidateMessageStackMultiPayload 校验 message.stack 放宽后的规则:
// ≥1 个 payload 生产层,且每层都在白名单内。空 stack / 非 payload 层报错;
// 多个合法 payload 层通过(与 standalone packet 多 payload 层拼接语义一致)。
func TestValidateMessageStackMultiPayload(t *testing.T) {
	baseStack := []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80}},
		{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "none", Close: "none"}},
	}
	flow := func(msg scenario.Message) scenario.FlowSpec {
		return scenario.FlowSpec{Name: "f", Stack: baseStack, Messages: []scenario.Message{msg}}
	}

	// 空 stack → 报错。
	if err := scenario.Validate(&scenario.Scenario{Flows: []scenario.FlowSpec{
		flow(scenario.Message{From: "src", Stack: nil}),
	}}); err == nil || !strings.Contains(err.Error(), "至少一个 payload 生产层") {
		t.Fatalf("空 message.stack 应报错,得到 %v", err)
	}

	// 含非 payload 层(eth) → 报错,并点名层索引与层名,引导 payload/payload_hex。
	if err := scenario.Validate(&scenario.Scenario{Flows: []scenario.FlowSpec{
		flow(scenario.Message{From: "src", Stack: []scenario.Layer{
			{Type: "payload", Fields: &scenario.PayloadFields{Payload: "aa"}},
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		}}),
	}}); err == nil || !strings.Contains(err.Error(), "stack[1]") || !strings.Contains(err.Error(), "eth") {
		t.Fatalf("含非 payload 层应报错并点名 stack[1]/eth,得到 %v", err)
	}

	// 两个合法 payload 层 → 通过。
	if err := scenario.Validate(&scenario.Scenario{Flows: []scenario.FlowSpec{
		flow(scenario.Message{From: "src", Stack: []scenario.Layer{
			{Type: "payload", Fields: &scenario.PayloadFields{Payload: "aaaa"}},
			{Type: "payload", Fields: &scenario.PayloadFields{Payload: "bbbb"}},
		}}),
	}}); err != nil {
		t.Fatalf("两个合法 payload 层应通过,得到 %v", err)
	}

	// 逐层字段校验:payload 同时配 payload+payload_hex(互斥)应被 validateLayer 拦截,
	// 而非静默通过推迟到 build。报错定位带 messages[0].stack[0].payload。
	if err := scenario.Validate(&scenario.Scenario{Flows: []scenario.FlowSpec{
		flow(scenario.Message{From: "src", Stack: []scenario.Layer{
			{Type: "payload", Fields: &scenario.PayloadFields{Payload: "aaaa", PayloadHex: "0x62626262"}},
		}}),
	}}); err == nil || !strings.Contains(err.Error(), "messages[0].stack[0].payload") ||
		!strings.Contains(err.Error(), "只能配置一个") {
		t.Fatalf("payload 同时配 payload+payload_hex 应被 validateLayer 拦截,得到 %v", err)
	}

	// 逐层字段校验(非首层):第二层 ftp_response code 越界也应被拦截,报错带 stack[1].ftp_response。
	if err := scenario.Validate(&scenario.Scenario{Flows: []scenario.FlowSpec{
		flow(scenario.Message{From: "src", Stack: []scenario.Layer{
			{Type: "payload", Fields: &scenario.PayloadFields{Payload: "aaaa"}},
			{Type: "ftp_response", Fields: &scenario.FTPResponseFields{Code: 99, Message: "x"}},
		}}),
	}}); err == nil || !strings.Contains(err.Error(), "messages[0].stack[1].ftp_response") {
		t.Fatalf("非首层 ftp_response code 越界应被 validateLayer 拦截,得到 %v", err)
	}

	// Type 与 Fields 不匹配:Type="eth" 却挂 PayloadFields。YAML 解码不会产出此状态,
	// 但 Layer 是导出类型,程序代码可直接构造。原实现只判 Fields 类型会放过它,导致
	// builder 按 Fields 产 payload 而 describe 按 Type 显示 "eth" 的不一致。现应拒绝,
	// 报错点名 Type "eth"(走"不支持"分支,因 isPayloadProducingLayer 校验映射不一致)。
	if err := scenario.Validate(&scenario.Scenario{Flows: []scenario.FlowSpec{
		flow(scenario.Message{From: "src", Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.PayloadFields{Payload: "aaaa"}},
		}}),
	}}); err == nil || !strings.Contains(err.Error(), "stack[0]") || !strings.Contains(err.Error(), "eth") {
		t.Fatalf("Type=eth 挂 PayloadFields(类型不匹配)应被拒绝并点名 eth,得到 %v", err)
	}
}

// TestStartAfterMessageLevelCycleRejected 验证事件粒度仍能拦住真正的跨流消息级环:
// a.msgA start_after b.msgB,b.msgB start_after a.msgA。
func TestStartAfterMessageLevelCycleRejected(t *testing.T) {
	flowA := "  - name: a\n    stack:\n" + flowStackYAML + `    messages:
      - from: src
        message_id: msgA
        start_after: "b.msgB"
        stack:
          - payload: { payload: "a\r\n" }
`
	flowB := "  - name: b\n    stack:\n" + flowStackYAML + `    messages:
      - from: src
        message_id: msgB
        start_after: "a.msgA"
        stack:
          - payload: { payload: "b\r\n" }
`
	err := loadValidateErr(t, "msgcycle.yaml", "link_type: ethernet\nflows:\n"+flowA+flowB)
	if err == nil {
		t.Fatal("期望 Validate 拒绝跨流消息级 2-环,实际通过")
	}
	if !strings.Contains(err.Error(), "循环依赖") {
		t.Errorf("错误应提及循环依赖,得到: %v", err)
	}
}

// udpFlowStackYAML 是最小合法 UDP 会话 flow.stack(YAML 形式,走 Load 完整解析路径)。
const udpFlowStackYAML = `      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.53" }
      - udp:  { sport: 49152, dport: 53 }
      - udp_session: {}
`

// TestValidateUDPSessionAccepts:udp_session 的两种等价写法({} 与 null)都过校验;
// message 从 src/dst 双向、多层 payload 均合法。
func TestValidateUDPSessionAccepts(t *testing.T) {
	for name, stack := range map[string]string{
		"空 map": udpFlowStackYAML,
		"null":  strings.Replace(udpFlowStackYAML, "udp_session: {}", "udp_session:", 1),
	} {
		t.Run(name, func(t *testing.T) {
			loadValid(t, "udp-ok.yaml", "link_type: ethernet\nflows:\n  - name: u\n    stack:\n"+stack+`    messages:
      - from: src
        stack:
          - payload: { payload: "query" }
      - from: dst
        stack:
          - payload: { payload: "answer" }
`)
		})
	}
	// message.stack 含 dns(UDP 会话的头号用例)合法;dns 进 TCP flow 被拒,补一例。
	loadValid(t, "udp-dns-ok.yaml", "link_type: ethernet\nflows:\n  - name: u\n    stack:\n"+udpFlowStackYAML+`    messages:
      - from: src
        stack:
          - dns: { id: 0x1234, qr: query, questions: [{ name: "example.com", type: A }] }
      - from: dst
        stack:
          - dns: { id: 0x1234, qr: response, answers: [{ name: "example.com", type: A, ttl: 300, data: "1.2.3.4" }] }
`)
	// UDP 会话的 message.stack 不按协议收窄:流式层(http_request)照常过校验,
	// 只产软告警(CheckUDPStreamAppLayer,见 flow_stack_test.go),畸形用例可故意为之。
	loadValid(t, "udp-http-raw.yaml", "link_type: ethernet\nflows:\n  - name: u\n    stack:\n"+udpFlowStackYAML+`    messages:
      - from: src
        stack:
          - http_request: { method: GET, url: /a }
`)
	err := loadValidateErr(t, "tcp-dns-bad.yaml", "link_type: ethernet\nflows:\n  - name: t\n    stack:\n"+flowStackYAML+`    messages:
      - from: src
        stack:
          - dns: { id: 0x1234, qr: query, questions: [{ name: "example.com", type: A }] }
`)
	if err == nil || !strings.Contains(err.Error(), "DNS over TCP 暂不支持") {
		t.Fatalf("TCP flow 的 message.stack 含 dns 应被拒,得到: %v", err)
	}
}

// TestValidateUDPSessionRejects:UDP 会话 flow 的 message 级约束(空 messages、
// segment、非 payload 层)与 udp_session 出现在 standalone packet 的拒绝。
func TestValidateUDPSessionRejects(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "空 messages",
			body: "link_type: ethernet\nflows:\n  - name: u\n    stack:\n" + udpFlowStackYAML,
			want: "UDP flow 的 messages 不能为空",
		},
		{
			name: "segment 被拒",
			body: "link_type: ethernet\nflows:\n  - name: u\n    stack:\n" + udpFlowStackYAML + `    messages:
      - from: src
        segment: { mss: 4 }
        stack:
          - payload: { payload: "abcdef" }
`,
			want: "UDP 无流重组,不支持 segment 切段",
		},
		{
			name: "udp_session 在 standalone packet 被拒",
			body: "link_type: ethernet\npackets:\n  - stack:\n" + udpFlowStackYAML + `      - payload: { payload: "hi" }
`,
			want: "udp_session 只能用于 flow.stack,不能出现在 standalone packet 的 stack 里",
		},
		{
			name: "udp_session 未知字段被拒",
			body: strings.Replace(
				"link_type: ethernet\nflows:\n  - name: u\n    stack:\n"+udpFlowStackYAML,
				"udp_session: {}", "udp_session: { timeout: 3 }", 1) + `    messages:
      - from: src
        stack:
          - payload: { payload: "hi" }
`,
			want: `不支持字段 "timeout"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 「未知字段」用例在解析层(Load)即报错,不走 Validate;其余走 Validate。
			path := writeScenario(t, "udp-bad.yaml", tc.body)
			s, err := scenario.Load(path)
			if err != nil {
				if strings.Contains(err.Error(), tc.want) {
					return // 解析层已拦截且文案匹配,视为通过
				}
				t.Fatalf("Load 失败(应可解析): %v", err)
			}
			err = scenario.Validate(s)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望报错含 %q,得到 %v", tc.want, err)
			}
		})
	}
}
