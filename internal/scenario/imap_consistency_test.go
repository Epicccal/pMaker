package scenario_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 imap_consistency.go 的 IMAP literal 计数覆盖值一致性告警
// (octets ≠ 实际字节数 → 软告警),对齐 ftp_consistency_test.go / multipart_consistency_test.go 风格。

// TestCheckIMAPLiteralConsistency: octets 覆盖值与实际字节数不一致产告警;一致或未覆盖则无告警。
func TestCheckIMAPLiteralConsistency(t *testing.T) {
	// data 内容 "hello" = 5 字节。
	cases := []struct {
		name     string
		octets   *int
		wantWarn bool
		warnSub  string
	}{
		{"未覆盖 octets(nil)不告警", nil, false, ""},
		{"octets 准确不告警", intPtr(5), false, ""},
		{"octets 撒谎告警", intPtr(9999), true, "9999"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lit := &scenario.IMAPLiteral{Data: "hello"}
			if tc.octets != nil {
				lit.Octets = tc.octets
			}
			s := &scenario.Scenario{Packets: []scenario.Packet{{
				Stack: imapBaseStack(imapRespLayer(scenario.IMAPResponseFields{
					Tag: "*", Data: "1 FETCH (BODY[] ", Literal: lit, Tail: ")",
				})),
			}}}
			ws := scenario.Warnings(s)
			if tc.wantWarn {
				found := false
				for _, w := range ws {
					if strings.Contains(w, "imap literal 计数不一致") && (tc.warnSub == "" || strings.Contains(w, tc.warnSub)) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("期望告警含 %q,得到: %v", tc.warnSub, ws)
				}
			} else {
				for _, w := range ws {
					if strings.Contains(w, "imap literal") {
						t.Errorf("不期望 imap literal 告警,得到: %v", w)
					}
				}
			}
		})
	}
}

// TestCheckIMAPLiteralConsistency_EML: eml 内容的告警口径(structured headers+body)。
func TestCheckIMAPLiteralConsistency_EML(t *testing.T) {
	// 结构化 eml:"From: a@b\r\n"(11) + "\r\n"(2) + "hi"(2) = 15 字节。
	eml := &scenario.EMLDataFields{
		Headers: scenario.HeaderMap{{Key: "From", Value: "a@b"}},
		Body:    "hi",
	}
	// 准确计数不告警。
	exact := 15
	s := &scenario.Scenario{Packets: []scenario.Packet{{
		Stack: imapBaseStack(imapRespLayer(scenario.IMAPResponseFields{
			Tag: "*", Data: "1 FETCH (BODY[] ",
			Literal: &scenario.IMAPLiteral{EML: eml, Octets: &exact}, Tail: ")",
		})),
	}}}
	ws := scenario.Warnings(s)
	for _, w := range ws {
		if strings.Contains(w, "imap literal") {
			t.Errorf("准确计数不应告警,得到: %v", w)
		}
	}

	// 撒谎告警。
	lie := 999
	s2 := &scenario.Scenario{Packets: []scenario.Packet{{
		Stack: imapBaseStack(imapRespLayer(scenario.IMAPResponseFields{
			Tag: "*", Data: "1 FETCH (BODY[] ",
			Literal: &scenario.IMAPLiteral{EML: eml, Octets: &lie}, Tail: ")",
		})),
	}}}
	ws2 := scenario.Warnings(s2)
	found := false
	for _, w := range ws2 {
		if strings.Contains(w, "imap literal 计数不一致") {
			found = true
		}
	}
	if !found {
		t.Errorf("撒谎 octets 应告警,得到: %v", ws2)
	}
}

// TestCheckIMAPLiteralConsistency_RequestFlow: imap_request 侧 literal 也覆盖(flow message)。
func TestCheckIMAPLiteralConsistency_RequestFlow(t *testing.T) {
	lie := 999
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{{
		Name: "imap",
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 143}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
		},
		Messages: []scenario.Message{{
			From: "src",
			Stack: []scenario.Layer{
				imapReqLayer(scenario.IMAPRequestFields{Tag: "a001", Command: "APPEND",
					Literal: &scenario.IMAPLiteral{Data: "hello", Octets: &lie}}),
			},
		}},
	}}}
	ws := scenario.Warnings(s)
	found := false
	for _, w := range ws {
		if strings.Contains(w, "imap literal 计数不一致") {
			found = true
		}
	}
	if !found {
		t.Errorf("flow message 内 imap_request literal 撒谎应告警,得到: %v", ws)
	}
}

// TestIMAPLiteralEMLBytes_EquivToBuilder 是跨包等价测试,把「靠人保持同步」变成「靠测试保持同步」:
// 同一组 EMLDataFields 喂入 scenario.IMAPLiteralEMLBytesForTest(IMAP literal octets 告警的
// 计数口径)与 builder.SerializeEMLData(eml_data 纯内容字节),断言两者逐字节相等。
// 一旦 builder/eml_data.go 的内容口径(headers + 空行 + 归一化 body、raw/raw_hex 透传)与
// scenario 侧 imapLiteralEMLBytes 漂移,本测试即失败。multipart 命中 ok=false 分支(场景
// 包内不算),单独验证其仍跳过而非误报。
func TestIMAPLiteralEMLBytes_EquivToBuilder(t *testing.T) {
	cases := []struct {
		name string
		f    *scenario.EMLDataFields
		// skip=true 表示 scenario 侧返回 ok=false(multipart),只验证不 panic 且 ok=false,
		// 不与 builder 比对(场景包内不算 multipart 字节)。
		skip bool
	}{
		{
			name: "结构化 headers+body",
			f: &scenario.EMLDataFields{
				Headers: scenario.HeaderMap{
					{Key: "From", Value: "alice@example.com"},
					{Key: "Subject", Value: "Hi"},
				},
				Body: "line one\nline two\r\n",
			},
		},
		{
			name: "结构化空 body(仅 headers)",
			f: &scenario.EMLDataFields{
				Headers: scenario.HeaderMap{{Key: "From", Value: "a@b"}},
			},
		},
		{
			name: "结构化重复头",
			f: &scenario.EMLDataFields{
				Headers: scenario.HeaderMap{
					{Key: "Received", Value: "by A"},
					{Key: "Received", Value: "by B"},
					{Key: "From", Value: "a@b"},
				},
				Body: "body\r\n",
			},
		},
		{
			name: "结构化 body 行首点(归一化后stuff 由接入层负责,内容层只产字节)",
			f: &scenario.EMLDataFields{
				Headers: scenario.HeaderMap{{Key: "From", Value: "a@b"}},
				Body:    ".dotline\nnormal\r\n",
			},
		},
		{
			name: "raw 裸透传(含裸 \\n 不归一化)",
			f: &scenario.EMLDataFields{
				Raw: "From: a\r\nTo: b\r\n\r\n.dotline\n",
			},
		},
		{
			name: "raw_hex",
			f: &scenario.EMLDataFields{
				RawHex: "0x466f6f", // "Foo"
			},
		},
		{
			name: "multipart(scenario 侧 ok=false)",
			f: &scenario.EMLDataFields{
				Headers: scenario.HeaderMap{
					{Key: "From", Value: "a@b"},
					{Key: "Content-Type", Value: "multipart/mixed; boundary=bnd"},
				},
				Multipart: &scenario.MultipartBody{
					Boundary: "bnd",
					Parts:    []scenario.MultipartPart{{Body: "part\r\n"}},
				},
			},
			skip: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := scenario.IMAPLiteralEMLBytesForTest(tc.f)
			if tc.skip {
				// multipart:scenario 侧不算字节,应返回 ok=false(跳过告警,不与 builder 比对)。
				if ok {
					t.Fatalf("multipart 应返回 ok=false,得到 %q", got)
				}
				return
			}
			if !ok {
				t.Fatalf("非 multipart 应返回 ok=true")
			}
			want, err := builder.SerializeEMLData(tc.f)
			if err != nil {
				t.Fatalf("builder.SerializeEMLData: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("imapLiteralEMLBytes 与 builder.SerializeEMLData 口径漂移:\ngot  %q\nwant %q", got, want)
			}
		})
	}
}
