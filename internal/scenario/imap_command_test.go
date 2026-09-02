package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 imap_command.go 的 IMAP 命令 / 响应字段合法基线校验,
// 对齐 pop3_command_test.go / smtp_command_test.go 的风格:三形式互斥、
// tag 字符集、命令表(大小写不敏感)、状态组/数据组互斥(决策 7)、
// literal 方向性(决策 8 + RFC §4.3)。

// imapReqLayer 包装一条 imap_request 层,便于表驱动构造。
func imapReqLayer(f scenario.IMAPRequestFields) scenario.Layer {
	return scenario.Layer{Type: "imap_request", Fields: &f}
}

// imapRespLayer 包装一条 imap_response 层。
func imapRespLayer(f scenario.IMAPResponseFields) scenario.Layer {
	return scenario.Layer{Type: "imap_response", Fields: &f}
}

// imapBaseStack 是承载 IMAP 校验的最小合法 stack(eth/ipv4/tcp),dport=143。
func imapBaseStack(layer scenario.Layer) []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 143}},
		layer,
	}
}

// TestValidateIMAPTag: tag 字符集(RFC 9051 §9:+ 排除、] 放行、atom-specials 拦截)。
func TestValidateIMAPTag(t *testing.T) {
	cases := []struct {
		name    string
		tag     string
		wantErr bool
		errSub  string
	}{
		{"合法 a001", "a001", false, ""},
		{"合法含 ]", "tag]x", false, ""},
		{"合法 A12345", "A12345", false, ""},
		{"空 tag", "", true, "需要 tag"},
		{"含 + 报错", "a+1", true, "+"},
		{"含 ( 报错", "a(b", true, "atom-specials"},
		{"含 ) 报错", "a)b", true, "atom-specials"},
		{"含 { 报错", "a{b", true, "atom-specials"},
		{"含 SP 报错", "a b", true, "atom-specials"},
		{"含 * 报错", "a*b", true, "atom-specials"},
		{"含 % 报错", "a%b", true, "atom-specials"},
		{"含 \" 报错", "a\"b", true, "atom-specials"},
		{"含 \\ 报错", "a\\b", true, "atom-specials"},
		{"含 CTL 报错", "a\x01b", true, "控制字符"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario.Scenario{Packets: []scenario.Packet{{
				Stack: imapBaseStack(imapReqLayer(scenario.IMAPRequestFields{Tag: tc.tag, Command: "NOOP"})),
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

// TestValidateIMAPCommand_KnownAccepts: RFC 9051 核心 + rev1 命令均通过(大小写不敏感)。
func TestValidateIMAPCommand_KnownAccepts(t *testing.T) {
	for _, cmd := range []string{"CAPABILITY", "logout", "NOOP", "LOGIN", "AUTHENTICATE", "STARTTLS",
		"APPEND", "SELECT", "FETCH", "STORE", "IDLE", "LSUB", "CHECK", "MOVE", "UID", "SEARCH"} {
		f := scenario.IMAPRequestFields{Tag: "a001", Command: cmd}
		// 必带 args 的命令补一个 args,避免被 args-required 规则先拦下。
		switch strings.ToUpper(cmd) {
		case "LOGIN", "AUTHENTICATE", "APPEND", "SELECT", "FETCH", "STORE", "SEARCH", "UID",
			"COPY", "MOVE", "CREATE", "DELETE", "LIST", "LSUB", "RENAME", "STATUS", "ENABLE",
			"SUBSCRIBE", "UNSUBSCRIBE", "EXAMINE":
			f.Args = "x"
		}
		s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: imapBaseStack(imapReqLayer(f))}}}
		err := scenario.Validate(s)
		if err != nil && strings.Contains(err.Error(), "未知 IMAP 命令") {
			t.Errorf("已知命令 %q 不应报\"未知命令\",得到: %v", cmd, err)
		}
	}
}

// TestValidateIMAPCommand_UnknownRejects: 非标/私有命令报错并引导 payload/payload_hex。
func TestValidateIMAPCommand_UnknownRejects(t *testing.T) {
	for _, cmd := range []string{"XFETCH", "LOGINX", "FOO"} {
		s := &scenario.Scenario{Packets: []scenario.Packet{{
			Stack: imapBaseStack(imapReqLayer(scenario.IMAPRequestFields{Tag: "a001", Command: cmd, Args: "x"})),
		}}}
		err := scenario.Validate(s)
		if err == nil || !strings.Contains(err.Error(), "未知 IMAP 命令") {
			t.Errorf("非标命令 %q 应报\"未知 IMAP 命令\"并引导 payload/payload_hex,得到: %v", cmd, err)
		}
	}
}

// TestValidateIMAPRequestFields_ThreeForms: 三形式互斥判别(命令行/裸行/literal 八位组)。
func TestValidateIMAPRequestFields_ThreeForms(t *testing.T) {
	cases := []struct {
		name    string
		f       scenario.IMAPRequestFields
		wantErr bool
		errSub  string
	}{
		// 形式 A:命令行
		{"命令行 NOOP", scenario.IMAPRequestFields{Tag: "a001", Command: "NOOP"}, false, ""},
		{"命令行 LOGIN 带 args", scenario.IMAPRequestFields{Tag: "a001", Command: "LOGIN", Args: "alice pass"}, false, ""},
		{"命令行 缺 tag", scenario.IMAPRequestFields{Command: "NOOP"}, true, "需要 tag"},
		{"命令行 缺 command", scenario.IMAPRequestFields{Tag: "a001"}, true, "需要 command"},
		// 形式 B:裸行
		{"裸行 DONE", scenario.IMAPRequestFields{Line: "DONE"}, false, ""},
		{"裸行 SASL base64", scenario.IMAPRequestFields{Line: "AGFsaWNlAHBhc3M="}, false, ""},
		// 裸行无参数位:尾随垃圾等畸形写进 line 本身,不借道 args
		{"裸行 DONE 带尾随垃圾", scenario.IMAPRequestFields{Line: "DONE junk"}, false, ""},
		// line 与 tag 互斥
		{"line+tag 互斥", scenario.IMAPRequestFields{Line: "DONE", Tag: "a001", Command: "NOOP"}, true, "互斥"},
		{"line+args 互斥", scenario.IMAPRequestFields{Line: "DONE", Args: "x"}, true, "互斥"},
		{"line+literal 互斥", scenario.IMAPRequestFields{Line: "DONE", Literal: &scenario.IMAPLiteral{Data: "x"}}, true, "互斥"},
		// 形式 C:literal.emit=data
		{"emit:data 独立八位组", scenario.IMAPRequestFields{Literal: &scenario.IMAPLiteral{Data: "x", Emit: "data"}}, false, ""},
		{"emit:data 带 tag 报错", scenario.IMAPRequestFields{Tag: "a001", Literal: &scenario.IMAPLiteral{Data: "x", Emit: "data"}}, true, "emit: data"},
		// CRLF 注入拦截
		{"args 含 LF", scenario.IMAPRequestFields{Tag: "a001", Command: "LOGIN", Args: "a\nb"}, true, "args"},
		{"line 含 CRLF", scenario.IMAPRequestFields{Line: "DONE\r\n"}, true, "line"},
		// args 策略:必带/禁带
		{"LOGIN 缺 args 报错", scenario.IMAPRequestFields{Tag: "a001", Command: "LOGIN"}, true, "需要 args"},
		{"NOOP 带 args 报错", scenario.IMAPRequestFields{Tag: "a001", Command: "NOOP", Args: "x"}, true, "不接受参数"},
		// APPEND 有 literal 时 args 可空
		{"APPEND 有 literal args 可空", scenario.IMAPRequestFields{Tag: "a001", Command: "APPEND", Literal: &scenario.IMAPLiteral{Data: "x"}}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: imapBaseStack(imapReqLayer(tc.f))}}}
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

// TestValidateIMAPResponseFields_TagStates: tag 三态定型(tag/"/"/"+")与字段分组。
func TestValidateIMAPResponseFields_TagStates(t *testing.T) {
	cases := []struct {
		name    string
		f       scenario.IMAPResponseFields
		wantErr bool
		errSub  string
	}{
		// tagged 状态响应
		{"tagged OK", scenario.IMAPResponseFields{Tag: "a001", Status: "OK", Text: "done"}, false, ""},
		{"tagged NO", scenario.IMAPResponseFields{Tag: "a001", Status: "NO", Text: "fail"}, false, ""},
		{"tagged PREAUTH 报错", scenario.IMAPResponseFields{Tag: "a001", Status: "PREAUTH", Text: "x"}, true, "OK / NO / BAD"},
		// untagged 状态响应
		{"untagged OK 带 code", scenario.IMAPResponseFields{Tag: "*", Status: "OK", Code: "UIDVALIDITY 123", Text: "UIDs valid"}, false, ""},
		{"untagged BYE", scenario.IMAPResponseFields{Tag: "*", Status: "BYE", Text: "logout"}, false, ""},
		{"untagged PREAUTH", scenario.IMAPResponseFields{Tag: "*", Status: "PREAUTH", Text: "x"}, false, ""},
		// untagged 数据响应
		{"untagged EXISTS", scenario.IMAPResponseFields{Tag: "*", Data: "42 EXISTS"}, false, ""},
		{"untagged FETCH 带 literal", scenario.IMAPResponseFields{
			Tag: "*", Data: "12 FETCH (BODY[HEADER] ",
			Literal: &scenario.IMAPLiteral{Data: "x"}, Tail: ")",
		}, false, ""},
		// continuation(text 可空:SASL 空挑战 "+ \r\n" 合法,RFC 9051 §9)
		{"continuation + text", scenario.IMAPResponseFields{Tag: "+", Text: "Ready"}, false, ""},
		{"continuation 空 text", scenario.IMAPResponseFields{Tag: "+"}, false, ""},
		{"continuation 带 status 报错", scenario.IMAPResponseFields{Tag: "+", Status: "OK", Text: "x"}, true, "continuation"},
		// 空 tag
		{"空 tag", scenario.IMAPResponseFields{Status: "OK", Text: "x"}, true, "需要 tag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: imapBaseStack(imapRespLayer(tc.f))}}}
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

// TestValidateIMAPResponseTag: 响应侧具体 tag 与 imap_request 走同一套字符集校验。
// "*" / "+" 是三态定型的分流符号(validateIMAPTag 的 atom-specials 会拒掉它们),须放行;
// 其余 tag 一旦漏校验就会被 serializeIMAPResp 原样落字节(CRLF 注入额外响应行、
// "*extra" 绕过 untagged 分流),故与 status/code/text/data/tail 的防护同级。
func TestValidateIMAPResponseTag(t *testing.T) {
	cases := []struct {
		name    string
		tag     string
		wantErr bool
		errSub  string
	}{
		{"合法 a001", "a001", false, ""},
		{"合法含 ]", "tag]x", false, ""},
		{"分流符号 *", "*", false, ""},
		{"含 CRLF 注入额外响应行", "a001\r\n* OK injected", true, "控制字符"},
		{"含 SP", "a b c", true, "atom-specials"},
		{"含 +", "tag+plus", true, "+"},
		{"含 * 绕过 untagged 分流", "*extra", true, "atom-specials"},
		{"含 CTL", "a\x01b", true, "控制字符"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := scenario.IMAPResponseFields{Tag: tc.tag, Status: "OK", Text: "hi"}
			s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: imapBaseStack(imapRespLayer(f))}}}
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

// TestValidateIMAPResponseFields_StatusDataMutex: 决策 7 状态组/数据组互斥五条。
func TestValidateIMAPResponseFields_StatusDataMutex(t *testing.T) {
	cases := []struct {
		name    string
		f       scenario.IMAPResponseFields
		wantErr bool
		errSub  string
	}{
		// 1. status 与 data 互斥
		{"status+data 互斥", scenario.IMAPResponseFields{Tag: "*", Status: "OK", Text: "x", Data: "42 EXISTS"}, true, "互斥"},
		// 2. data 首 token 不得为状态词(封死状态响应误写进 data)
		{"data 首词 OK 报错", scenario.IMAPResponseFields{Tag: "*", Data: "OK [UIDVALIDITY 1] UIDs valid"}, true, "首 token"},
		{"data 首词 bye 报错", scenario.IMAPResponseFields{Tag: "*", Data: "BYE logout"}, true, "首 token"},
		{"data 首词 OKAY 合法(不是状态词)", scenario.IMAPResponseFields{Tag: "*", Data: "OKAY something"}, false, ""},
		// 3. data 非空时 tag 必须是 *
		{"data 带 tagged 报错", scenario.IMAPResponseFields{Tag: "a001", Data: "42 EXISTS"}, true, "untagged"},
		// 4. code/text 不得与 data 同现;literal/tail 须依附 data
		{"data+text 同现报错", scenario.IMAPResponseFields{Tag: "*", Data: "42 EXISTS", Text: "x"}, true, "状态组"},
		{"literal 无 data 报错", scenario.IMAPResponseFields{Tag: "*", Literal: &scenario.IMAPLiteral{Data: "x"}}, true, "依附"},
		{"tail 无 data 报错", scenario.IMAPResponseFields{Tag: "*", Tail: ")"}, true, "依附"},
		// 5. 全空报错
		{"全空响应报错", scenario.IMAPResponseFields{Tag: "*"}, true, "需要"},
		// text/code 不得脱离 status 单独存在(builder 会静默丢弃,产出畸形 prefix CRLF)
		{"孤儿 text 报错", scenario.IMAPResponseFields{Tag: "a001", Text: "orphan text"}, true, "需要"},
		{"孤儿 code+text 报错", scenario.IMAPResponseFields{Tag: "*", Code: "UIDVALIDITY 1", Text: "valid"}, true, "需要"},
		// code 含 ] 报错
		{"code 含 ] 报错", scenario.IMAPResponseFields{Tag: "*", Status: "OK", Code: "UIDVALIDITY]1", Text: "x"}, true, "]"},
		// CRLF 注入
		{"text 含 CRLF 报错", scenario.IMAPResponseFields{Tag: "a001", Status: "OK", Text: "x\r\n"}, true, "text"},
		{"data 含 CRLF 报错", scenario.IMAPResponseFields{Tag: "*", Data: "42\r\nEXISTS"}, true, "data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: imapBaseStack(imapRespLayer(tc.f))}}}
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

// TestValidateIMAPLiteral: literal 校验(三选一/方向性/决策 8)。
func TestValidateIMAPLiteral(t *testing.T) {
	syncFalse := false
	cases := []struct {
		name       string
		lit        *scenario.IMAPLiteral
		fromServer bool // true = imap_response 下
		wantErr    bool
		errSub     string
	}{
		// 三选一
		{"eml 内容", &scenario.IMAPLiteral{EML: &scenario.EMLDataFields{Raw: "x"}}, false, false, ""},
		{"data 内容", &scenario.IMAPLiteral{Data: "x"}, false, false, ""},
		{"data_hex 内容", &scenario.IMAPLiteral{DataHex: "0x01"}, false, false, ""},
		{"全空报错", &scenario.IMAPLiteral{}, false, true, "需要"},
		{"eml+data 互斥", &scenario.IMAPLiteral{EML: &scenario.EMLDataFields{Raw: "x"}, Data: "y"}, false, true, "只能配置一个"},
		{"非法 hex", &scenario.IMAPLiteral{DataHex: "0xZZ"}, false, true, "data_hex"},
		// emit
		{"非法 emit", &scenario.IMAPLiteral{Data: "x", Emit: "zzz"}, false, true, "emit"},
		{"emit prefix 合法", &scenario.IMAPLiteral{Data: "x", Emit: "prefix"}, false, false, ""},
		// octets
		{"octets 负值报错", &scenario.IMAPLiteral{Data: "x", Octets: intPtr(-1)}, false, true, "负"},
		{"octets 撒谎合法(软告警)", &scenario.IMAPLiteral{Data: "x", Octets: intPtr(9999)}, false, false, ""},
		// 方向性:server 侧 sync:false 报错
		{"server 非同步 literal 报错", &scenario.IMAPLiteral{Data: "x", Sync: &syncFalse}, true, true, "MUST NOT"},
		// 决策 8:binary + sync:false 报错
		{"binary+sync:false 报错", &scenario.IMAPLiteral{Data: "x", Binary: true, Sync: &syncFalse}, false, true, "literal8"},
		{"binary sync:true 合法", &scenario.IMAPLiteral{Data: "x", Binary: true}, false, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var l scenario.Layer
			if tc.fromServer {
				l = imapRespLayer(scenario.IMAPResponseFields{Tag: "*", Data: "x", Literal: tc.lit})
			} else {
				l = imapReqLayer(scenario.IMAPRequestFields{Tag: "a001", Command: "APPEND", Literal: tc.lit})
			}
			s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: imapBaseStack(l)}}}
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

// intPtr 返回 int 的指针(测试辅助)。
func intPtr(v int) *int { return &v }
