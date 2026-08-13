package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 smtp_request.go 的 SMTP 信封 verb / 响应码合法基线校验,
// 对齐 ftp_command_test.go 的风格:已知 verb(大小写不敏感)、合法响应码(200-559)、
// 未知值报错并引导 payload / payload_hex。并覆盖 verb 参数要求(EHLO 必带/QUIT 禁带)、
// MAIL/RCPT 信封字段约束(from 三态、to 非空、禁 args、params 仅 MAIL/RCPT)。

// smtpCmdLayer 包装一条 smtp_request 层,便于表驱动构造。
func smtpCmdLayer(verb string, f scenario.SMTPRequestFields) scenario.Layer {
	f.Verb = verb
	return scenario.Layer{Type: "smtp_request", Fields: &f}
}

// smtpRespLayer 包装一条 smtp_response 层。
func smtpRespLayer(code int, msg string) scenario.Layer {
	return scenario.Layer{Type: "smtp_response", Fields: &scenario.SMTPResponseFields{Code: code, Message: msg}}
}

// smtpBaseStack 是承载 SMTP 校验的最小合法 stack(eth/ipv4/tcp),供包内测试直接构造 Scenario。
func smtpBaseStack(layer scenario.Layer) []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 25}},
		layer,
	}
}

// strPtr 是 *string 字面便利构造(用于 from 三态测试)。
func strPtr(s string) *string { return &s }

// TestValidateSMTPVerb_KnownAccepts: RFC 5321 核心与常见扩展 verb 均通过(大小写不敏感)。
func TestValidateSMTPVerb_KnownAccepts(t *testing.T) {
	for _, verb := range []string{"EHLO", "helo", "MAIL", "Rcpt", "DATA", "AUTH", "STARTTLS", "BDAT", "ETRN", "QUIT"} {
		s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer(verb, scenario.SMTPRequestFields{}))}}}
		// 多数 verb 需要 args 或信封字段;这里只验 verb 身份被接受(后续用例细化字段)。
		// EHLO/HELO/VRFY 等必带 args 会报错,但报错不应是"未知 verb"。
		err := scenario.Validate(s)
		if err != nil && strings.Contains(err.Error(), "未知 SMTP verb") {
			t.Errorf("已知 verb %q 不应报\"未知 verb\",得到: %v", verb, err)
		}
	}
}

// TestValidateSMTPVerb_UnknownRejects: 拼写错误与私有 verb 报错并引导 payload / payload_hex。
func TestValidateSMTPVerb_UnknownRejects(t *testing.T) {
	for _, verb := range []string{"XMSG", "MAILX", "HELOO", "FOO"} {
		s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer(verb, scenario.SMTPRequestFields{}))}}}
		err := scenario.Validate(s)
		if err == nil {
			t.Fatalf("未知 verb %q 应被拒,实际通过", verb)
		}
		if !strings.Contains(err.Error(), verb) {
			t.Errorf("错误应点名 verb %q,得到: %v", verb, err)
		}
		if !strings.Contains(err.Error(), "payload") || !strings.Contains(err.Error(), "payload_hex") {
			t.Errorf("错误应引导 payload / payload_hex,得到: %v", err)
		}
	}
}

// TestValidateSMTPVerb_EmptyRejects: 空 verb 报错。
func TestValidateSMTPVerb_EmptyRejects(t *testing.T) {
	s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer("", scenario.SMTPRequestFields{}))}}}
	err := scenario.Validate(s)
	if err == nil || !strings.Contains(err.Error(), "verb") {
		t.Fatalf("空 verb 应报错,得到: %v", err)
	}
}

// TestValidateSMTPRequest_VerbArgsRule: EHLO 必带 args / QUIT 禁带 args / DATA 禁带 / NOOP 可选。
func TestValidateSMTPRequest_VerbArgsRule(t *testing.T) {
	cases := []struct {
		name    string
		verb    string
		args    string
		wantErr bool
		substr  string
	}{
		{"EHLO 带域名通过", "EHLO", "client.example", false, ""},
		{"EHLO 缺 args 报错", "EHLO", "", true, "需要 args"},
		{"QUIT 无 args 通过", "QUIT", "", false, ""},
		{"QUIT 带 args 报错", "QUIT", "foo", true, "不接受参数"},
		{"DATA 带 args 报错", "DATA", "foo", true, "不接受参数"},
		{"NOOP 无 args 通过", "NOOP", "", false, ""},
		{"NOOP 带 args 通过", "NOOP", "echo", false, ""},
		{"AUTH 带 PLAIN 通过", "AUTH", "PLAIN dGVzdA==", false, ""},
		{"AUTH 缺 args 报错", "AUTH", "", true, "需要 args"},
		{"VRFY 缺 args 报错", "VRFY", "", true, "需要 args"},
		{"STARTTLS 带 args 报错", "STARTTLS", "foo", true, "不接受参数"},
		{"RSET 无 args 通过", "RSET", "", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer(c.verb, scenario.SMTPRequestFields{Args: c.args}))}}}
			err := scenario.Validate(s)
			if c.wantErr {
				if err == nil {
					t.Fatalf("期望报错,实际通过")
				}
				if !strings.Contains(err.Error(), c.substr) {
					t.Errorf("错误应含 %q,得到: %v", c.substr, err)
				}
			} else if err != nil {
				t.Errorf("期望通过,得到: %v", err)
			}
		})
	}
}

// TestValidateSMTPRequest_MailFromThreeStates: from 三态(nil 报错 / "" → <> / "addr" → <addr>)。
func TestValidateSMTPRequest_MailFromThreeStates(t *testing.T) {
	cases := []struct {
		name    string
		from    *string
		wantErr bool
		substr  string
	}{
		{"未给出 from 报错", nil, true, "需要 from"},
		{"显式空串 from 通过(退信)", strPtr(""), false, ""},
		{"地址 from 通过", strPtr("alice@example.com"), false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer("MAIL", scenario.SMTPRequestFields{From: c.from}))}}}
			err := scenario.Validate(s)
			if c.wantErr {
				if err == nil || !strings.Contains(err.Error(), c.substr) {
					t.Fatalf("期望报错含 %q,得到: %v", c.substr, err)
				}
			} else if err != nil {
				t.Errorf("期望通过,得到: %v", err)
			}
		})
	}
}

// TestValidateSMTPRequest_RcptConstraints: RCPT 须 to 非空,禁 from,禁 args。
func TestValidateSMTPRequest_RcptConstraints(t *testing.T) {
	// RCPT 缺 to 报错。
	s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer("RCPT", scenario.SMTPRequestFields{}))}}}
	if err := scenario.Validate(s); err == nil || !strings.Contains(err.Error(), "需要 to") {
		t.Errorf("RCPT 缺 to 应报错,得到: %v", err)
	}
	// RCPT 带 from 报错。
	s = &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer("RCPT", scenario.SMTPRequestFields{To: "bob@example.net", From: strPtr("a@b")}))}}}
	if err := scenario.Validate(s); err == nil || !strings.Contains(err.Error(), "不支持 from") {
		t.Errorf("RCPT 带 from 应报错,得到: %v", err)
	}
	// RCPT 带 args 报错。
	s = &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer("RCPT", scenario.SMTPRequestFields{To: "bob@example.net", Args: "foo"}))}}}
	if err := scenario.Validate(s); err == nil || !strings.Contains(err.Error(), "args") {
		t.Errorf("RCPT 带 args 应报错,得到: %v", err)
	}
	// RCPT 合法通过。
	s = &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer("RCPT", scenario.SMTPRequestFields{To: "bob@example.net"}))}}}
	if err := scenario.Validate(s); err != nil {
		t.Errorf("合法 RCPT 应通过,得到: %v", err)
	}
}

// TestValidateSMTPRequest_MailForbidsToAndArgs: MAIL 禁 to、禁 args。
func TestValidateSMTPRequest_MailForbidsToAndArgs(t *testing.T) {
	// MAIL 带 to 报错。
	s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer("MAIL", scenario.SMTPRequestFields{From: strPtr("a@b"), To: "x@y"}))}}}
	if err := scenario.Validate(s); err == nil || !strings.Contains(err.Error(), "不支持 to") {
		t.Errorf("MAIL 带 to 应报错,得到: %v", err)
	}
	// MAIL 带 args 报错。
	s = &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer("MAIL", scenario.SMTPRequestFields{From: strPtr("a@b"), Args: "foo"}))}}}
	if err := scenario.Validate(s); err == nil || !strings.Contains(err.Error(), "args") {
		t.Errorf("MAIL 带 args 应报错,得到: %v", err)
	}
}

// TestValidateSMTPRequest_ParamsOnlyMailRcpt: params 给非 MAIL/RCPT verb 报错。
func TestValidateSMTPRequest_ParamsOnlyMailRcpt(t *testing.T) {
	s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer("EHLO", scenario.SMTPRequestFields{Args: "client", Params: scenario.HeaderMap{{Key: "SIZE", Value: "10"}}}))}}}
	if err := scenario.Validate(s); err == nil || !strings.Contains(err.Error(), "params") {
		t.Errorf("非 MAIL/RCPT verb 带 params 应报错,得到: %v", err)
	}
	// MAIL 带 params 通过。
	s = &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer("MAIL", scenario.SMTPRequestFields{From: strPtr("a@b"), Params: scenario.HeaderMap{{Key: "SIZE", Value: "10"}}}))}}}
	if err := scenario.Validate(s); err != nil {
		t.Errorf("MAIL 带 params 应通过,得到: %v", err)
	}
}

// TestValidateSMTPRequest_NonMailRcptForbidsFromTo: 非 MAIL/RCPT verb 禁 from/to。
func TestValidateSMTPRequest_NonMailRcptForbidsFromTo(t *testing.T) {
	// EHLO 带 from 报错。
	s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer("EHLO", scenario.SMTPRequestFields{Args: "client", From: strPtr("a@b")}))}}}
	if err := scenario.Validate(s); err == nil || !strings.Contains(err.Error(), "from") {
		t.Errorf("EHLO 带 from 应报错,得到: %v", err)
	}
	// EHLO 带 to 报错。
	s = &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpCmdLayer("EHLO", scenario.SMTPRequestFields{Args: "client", To: "x@y"}))}}}
	if err := scenario.Validate(s); err == nil || !strings.Contains(err.Error(), "to") {
		t.Errorf("EHLO 带 to 应报错,得到: %v", err)
	}
}

// TestValidateSMTPResponseCode_ValidAccepts: 200-559 范围内的合法码通过。
func TestValidateSMTPResponseCode_ValidAccepts(t *testing.T) {
	for _, code := range []int{200, 220, 235, 250, 354, 421, 550, 553, 559} {
		s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpRespLayer(code, "msg"))}}}
		if err := scenario.Validate(s); err != nil {
			t.Errorf("合法响应码 %d 应通过,得到: %v", code, err)
		}
	}
}

// TestValidateSMTPResponseCode_OutOfRangeRejects: 99 / 199 / 560 / 负数等非法位数报错,
// 以及 260-299/360-399/460-499/590-599 等十位越界(虽落在 200-559 区间内但 RFC 5321 文法非法)报错。
// 错误信息按越界种类分支:非三位 → "必须是三位";百位越界 → "百位须 2-5";十位越界 → "十位须 0-5"。
func TestValidateSMTPResponseCode_OutOfRangeRejects(t *testing.T) {
	cases := []struct {
		code   int
		substr string
	}{
		{0, "必须是三位"}, {99, "必须是三位"}, {1000, "必须是三位"}, {-1, "必须是三位"},
		{199, "百位须 2-5"}, {600, "百位须 2-5"},
		{560, "十位须 0-5"}, {590, "十位须 0-5"}, {599, "十位须 0-5"},
		{260, "十位须 0-5"}, {299, "十位须 0-5"}, {360, "十位须 0-5"},
		{399, "十位须 0-5"}, {460, "十位须 0-5"}, {499, "十位须 0-5"},
	}
	for _, c := range cases {
		s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpRespLayer(c.code, "msg"))}}}
		err := scenario.Validate(s)
		if err == nil {
			t.Fatalf("非法响应码 %d 应被拒,实际通过", c.code)
		}
		if !strings.Contains(err.Error(), c.substr) {
			t.Errorf("code %d 错误应含 %q,得到: %v", c.code, c.substr, err)
		}
		if !strings.Contains(err.Error(), "payload") || !strings.Contains(err.Error(), "payload_hex") {
			t.Errorf("code %d 错误应引导 payload / payload_hex,得到: %v", c.code, err)
		}
	}
}

// TestValidateSMTPResponse_MessageOrLinesRequired: code 合法但缺 message/lines 报错;两者同设报错。
func TestValidateSMTPResponse_MessageOrLinesRequired(t *testing.T) {
	// 缺 message/lines 报错。
	s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(smtpRespLayer(220, ""))}}}
	if err := scenario.Validate(s); err == nil || !strings.Contains(err.Error(), "message") {
		t.Fatalf("合法 code 但缺 message/lines 应报错,得到: %v", err)
	}
	// 两者同设报错(用完整 stack 走 validateLayer)。
	s = &scenario.Scenario{Packets: []scenario.Packet{{Stack: smtpBaseStack(scenario.Layer{Type: "smtp_response", Fields: &scenario.SMTPResponseFields{Code: 250, Message: "OK", Lines: []string{"a"}}})}}}
	if err := scenario.Validate(s); err == nil || !strings.Contains(err.Error(), "只能配置一个") {
		t.Errorf("message 与 lines 同设应报错,得到: %v", err)
	}
}
