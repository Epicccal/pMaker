package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 pop3_command.go 的 POP3 命令 / 状态指示符合法基线校验,
// 对齐 smtp_command_test.go / ftp_command_test.go 的风格:已知命令(大小写不敏感)、
// 合法状态指示符(+OK/-ERR)、未知值报错并引导 payload / payload_hex。并覆盖命令
// 参数要求(RETR 必带/QUIT 禁带/LIST 可选)、pop3_response 字段互斥(message/lines/eml)。

// pop3CmdLayer 包装一条 pop3_request 层,便于表驱动构造。
func pop3CmdLayer(command string, f scenario.POP3RequestFields) scenario.Layer {
	f.Command = command
	return scenario.Layer{Type: "pop3_request", Fields: &f}
}

// pop3RespLayer 包装一条 pop3_response 层。
func pop3RespLayer(status, msg string) scenario.Layer {
	return scenario.Layer{Type: "pop3_response", Fields: &scenario.POP3ResponseFields{Status: status, Message: msg}}
}

// pop3BaseStack 是承载 POP3 校验的最小合法 stack(eth/ipv4/tcp),供包内测试直接构造 Scenario。
func pop3BaseStack(layer scenario.Layer) []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 110}},
		layer,
	}
}

// TestValidatePOP3Command_KnownAccepts: RFC 1939 核心与扩展命令均通过(大小写不敏感)。
func TestValidatePOP3Command_KnownAccepts(t *testing.T) {
	for _, cmd := range []string{"USER", "pass", "APOP", "STAT", "LIST", "retr", "DELE", "NOOP", "RSET", "TOP", "UIDL", "QUIT", "CAPA", "STLS", "AUTH"} {
		s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: pop3BaseStack(pop3CmdLayer(cmd, scenario.POP3RequestFields{}))}}}
		// 多数命令需要 args;此处只验命令身份被接受(后续用例细化字段)。
		// 必带 args 的命令会报错,但不应是"未知命令"。
		err := scenario.Validate(s)
		if err != nil && strings.Contains(err.Error(), "未知 POP3 命令") {
			t.Errorf("已知命令 %q 不应报\"未知命令\",得到: %v", cmd, err)
		}
	}
}

// TestValidatePOP3Command_UnknownRejects: 非标/私有命令报错并引导 payload/payload_hex。
func TestValidatePOP3Command_UnknownRejects(t *testing.T) {
	for _, cmd := range []string{"XLIST", "FETCH", "LOGIN"} {
		s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: pop3BaseStack(pop3CmdLayer(cmd, scenario.POP3RequestFields{}))}}}
		err := scenario.Validate(s)
		if err == nil || !strings.Contains(err.Error(), "未知 POP3 命令") {
			t.Errorf("非标命令 %q 应报\"未知 POP3 命令\"并引导 payload/payload_hex,得到: %v", cmd, err)
		}
	}
}

// TestValidatePOP3Command_Empty: 空 command 报错。
func TestValidatePOP3Command_Empty(t *testing.T) {
	s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: pop3BaseStack(pop3CmdLayer("", scenario.POP3RequestFields{}))}}}
	err := scenario.Validate(s)
	if err == nil || !strings.Contains(err.Error(), "需要 command") {
		t.Errorf("空 command 应报\"需要 command\",得到: %v", err)
	}
}

// TestValidatePOP3RequestFields_ArgsRules: 命令参数要求(required/forbidden/optional)。
func TestValidatePOP3RequestFields_ArgsRules(t *testing.T) {
	cases := []struct {
		name    string
		command string
		args    string
		wantErr bool
	}{
		// 必带 args:RETR 需要 msg#
		{"RETR 需 args", "RETR", "", true},
		{"RETR 带 args", "RETR", "1", false},
		{"USER 需 args", "USER", "", true},
		{"USER 带 args", "USER", "alice", false},
		{"PASS 需 args", "PASS", "", true},
		{"TOP 需 args", "TOP", "1 10", false},
		{"APOP 需 args", "APOP", "alice digest", false},
		{"AUTH 需 args", "AUTH", "PLAIN", false},
		// 禁带 args:STAT/NOOP/RSET/QUIT/CAPA/STLS
		{"STAT 禁 args", "STAT", "1", true},
		{"STAT 无 args", "STAT", "", false},
		{"NOOP 禁 args", "NOOP", "x", true},
		{"QUIT 无 args", "QUIT", "", false},
		{"CAPA 禁 args", "CAPA", "x", true},
		{"STLS 禁 args", "STLS", "x", true},
		// CRLF 注入拦截:args 含换行符应报错
		{"RETR args 含 LF", "RETR", "1\n", true},
		{"RETR args 含 CRLF", "RETR", "1\r\n", true},
		{"USER args 含 CR", "USER", "alice\r", true},
		// CRLF 拦截在 args 有/无规则之前:空 args 已由 required 规则拦截,这里只测非空含换行
		{"LIST 无 args", "LIST", "", false},
		{"LIST 带 args", "LIST", "1", false},
		{"UIDL 无 args", "UIDL", "", false},
		{"UIDL 带 args", "UIDL", "1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario.Scenario{Packets: []scenario.Packet{{
				Stack: pop3BaseStack(pop3CmdLayer(tc.command, scenario.POP3RequestFields{Args: tc.args})),
			}}}
			err := scenario.Validate(s)
			if tc.wantErr && err == nil {
				t.Errorf("期望报错,实际通过")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("不期望报错,得到: %v", err)
			}
		})
	}
}

// TestValidatePOP3ResponseFields_StatusRules: 状态指示符 +OK/-ERR/+(大小写不敏感),非标报错。
// + 是 RFC 1734/4954 SASL 续行挑战(单字符 + 而非 +OK)。
func TestValidatePOP3ResponseFields_StatusRules(t *testing.T) {
	cases := []struct {
		name    string
		status  string
		wantErr bool
		errSub  string
	}{
		{"+OK", "+OK", false, ""},
		{"-ERR", "-ERR", false, ""},
		{"+ SASL 续行", "+", false, ""},
		{"+ok 小写", "+ok", false, ""},
		{"-err 小写", "-err", false, ""},
		{"+ 小写", "+", false, ""},
		{"空 status", "", true, "需要 status"},
		{"非标 +FOO", "+FOO", true, "非法"},
		{"非标 OK", "OK", true, "非法"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario.Scenario{Packets: []scenario.Packet{{
				Stack: pop3BaseStack(pop3RespLayer(tc.status, "msg")),
			}}}
			err := scenario.Validate(s)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("期望报错,实际通过")
				}
				if tc.errSub != "" && !strings.Contains(err.Error(), tc.errSub) {
					t.Errorf("错误应含 %q,得到: %v", tc.errSub, err)
				}
			} else if err != nil {
				t.Errorf("不期望报错,得到: %v", err)
			}
		})
	}
}

// TestValidatePOP3ResponseFields_MultilineStatusOnlyOK: 多行正文(lines/eml)仅 +OK 可用;
// -ERR 永远单行,RFC 1734/4954 SASL 续行 + 也是单行挑战。二者搭配 lines/eml 报错并引导 payload/payload_hex。
func TestValidatePOP3ResponseFields_MultilineStatusOnlyOK(t *testing.T) {
	cases := []struct {
		name    string
		status  string
		lines   []string
		eml     *scenario.EMLDataFields
		wantErr bool
		errSub  string
	}{
		// -ERR 搭配多行正文(RFC 1939 不存在的形态)
		{"-ERR + lines", "-ERR", []string{"a", "b"}, nil, true, "永远单行"},
		{"-ERR + eml", "-ERR", nil, &scenario.EMLDataFields{Raw: "x"}, true, "永远单行"},
		{"-ERR + lines + message", "-ERR", []string{"a"}, nil, true, "永远单行"},
		// + SASL 续行搭配多行正文
		{"+ + lines", "+", []string{"a"}, nil, true, "SASL 续行挑战"},
		{"+ + eml", "+", nil, &scenario.EMLDataFields{Raw: "x"}, true, "SASL 续行挑战"},
		// 大小写不敏感
		{"-err 小写 + lines", "-err", []string{"a"}, nil, true, "永远单行"},
		// 合法基线对照:+OK 多行通过(含 message)
		{"+OK + lines 合法", "+OK", []string{"a", "b"}, nil, false, ""},
		{"+OK + eml 合法", "+OK", nil, &scenario.EMLDataFields{
			Headers: scenario.HeaderMap{{Key: "From", Value: "a@b"}}, Body: "hi"}, false, ""},
		// -ERR / + 的单行形态(message)合法
		{"-ERR + message 单行", "-ERR", nil, nil, false, ""},
		{"+ + message 单行", "+", nil, nil, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario.Scenario{Packets: []scenario.Packet{{
				Stack: pop3BaseStack(scenario.Layer{Type: "pop3_response", Fields: &scenario.POP3ResponseFields{
					Status:  tc.status,
					Message: "msg", // 单行响应需有 message 否则会先命中"需要 message"校验
					Lines:   tc.lines,
					EML:     tc.eml,
				}}),
			}}}
			err := scenario.Validate(s)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("期望报错,实际通过")
				}
				if tc.errSub != "" && !strings.Contains(err.Error(), tc.errSub) {
					t.Errorf("错误应含 %q,得到: %v", tc.errSub, err)
				}
			} else if err != nil {
				t.Errorf("不期望报错,得到: %v", err)
			}
		})
	}
}

// TestValidatePOP3ResponseFields_MutualExclusion: message 可与 lines/eml 组合(单行或多行首行带文本);
// lines 与 eml 互斥;message/lines/eml 至少其一非空。
func TestValidatePOP3ResponseFields_MutualExclusion(t *testing.T) {
	cases := []struct {
		name    string
		status  string
		message string
		lines   []string
		eml     *scenario.EMLDataFields
		wantErr bool
		errSub  string
	}{
		// 合法组合
		{
			name:   "message+lines 多行首行带文本(LIST 形态)",
			status: "+OK", message: "2 messages (320 octets)",
			lines: []string{"1 1200", "2 2000"},
		},
		{
			name:   "message+eml 多行首行带文本+正文",
			status: "+OK", message: "message 1 follows",
			eml: &scenario.EMLDataFields{
				Headers: scenario.HeaderMap{{Key: "From", Value: "a@b"}},
				Body:    "hi",
			},
		},
		{
			name:   "仅 eml 合法 EML 内容",
			status: "+OK",
			eml: &scenario.EMLDataFields{
				Headers: scenario.HeaderMap{{Key: "From", Value: "a@b"}},
				Body:    "hi",
			},
		},
		// CRLF 注入拦截:message 或 lines 元素含换行符应报错
		{
			name:    "message 含 LF 注入",
			status:  "+OK",
			message: "ok\ninjected",
			wantErr: true,
			errSub:  "message",
		},
		{
			name:    "message 含 CRLF 注入",
			status:  "+OK",
			message: "ok\r\n+OK injected",
			wantErr: true,
			errSub:  "message",
		},
		{
			name:    "lines[0] 含 CRLF 注入",
			status:  "+OK",
			lines:   []string{"1 1200\r\nDELE 1"},
			wantErr: true,
			errSub:  "lines[0]",
		},
		{
			name:    "lines[1] 含 LF 注入",
			status:  "+OK",
			lines:   []string{"1 1200", "2 840\ninjected"},
			wantErr: true,
			errSub:  "lines[1]",
		},
		// lines 元素合法(无换行)
		{
			name:   "lines 合法无换行",
			status: "+OK",
			lines:  []string{"1 1200", "2 840"},
		},
		// 错误组合
		{
			name:    "lines+eml 互斥",
			status:  "+OK",
			lines:   []string{"a"},
			eml:     &scenario.EMLDataFields{Raw: "x"},
			wantErr: true,
			errSub:  "互斥",
		},
		{
			name:    "裸 status 行缺 message/lines/eml",
			status:  "+OK",
			wantErr: true,
			errSub:  "需要 message / lines / eml",
		},
		{
			name:    "eml 子结构全空委托校验报错",
			status:  "+OK",
			eml:     &scenario.EMLDataFields{},
			wantErr: true,
			errSub:  "eml:",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario.Scenario{Packets: []scenario.Packet{{
				Stack: pop3BaseStack(scenario.Layer{Type: "pop3_response", Fields: &scenario.POP3ResponseFields{
					Status:  tc.status,
					Message: tc.message,
					Lines:   tc.lines,
					EML:     tc.eml,
				}}),
			}}}
			err := scenario.Validate(s)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("期望报错,实际通过")
				}
				if tc.errSub != "" && !strings.Contains(err.Error(), tc.errSub) {
					t.Errorf("错误应含 %q,得到: %v", tc.errSub, err)
				}
			} else if err != nil {
				t.Errorf("不期望报错,得到: %v", err)
			}
		})
	}
}
