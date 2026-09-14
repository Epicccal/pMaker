package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 multipart 子结构校验(validateMultipart / validateBoundary)与一致性告警
// (CheckMultipartConsistency),通过 Validate 与 Warnings 直接驱动。校验只判合法性,
// 不改变序列化(序列化在 builder/multipart.go)。

// multipartLayer 把 multipart 包进 http_request,便于复用 Validate 路径。
func multipartHTTPReq(m *scenario.MultipartBody) *scenario.HTTPReqFields {
	return &scenario.HTTPReqFields{
		Method:    "POST",
		URL:       "/upload",
		Headers:   scenario.HeaderMap{{Key: "Content-Type", Value: "multipart/form-data; boundary=----=_pMaker_0001"}},
		Multipart: m,
	}
}

func TestValidateMultipart_OK(t *testing.T) {
	cases := []struct {
		name string
		m    *scenario.MultipartBody
	}{
		{
			"单 part 文本",
			&scenario.MultipartBody{
				Parts: []scenario.MultipartPart{{
					Headers: scenario.HeaderMap{{Key: "Content-Disposition", Value: `form-data; name="f"`}},
					Body:    "v",
				}},
			},
		},
		{
			"显式合法 boundary",
			&scenario.MultipartBody{
				Boundary: "my-boundary_123",
				Parts:    []scenario.MultipartPart{{Body: "x"}},
			},
		},
		{
			"body_hex + base64",
			&scenario.MultipartBody{
				Parts: []scenario.MultipartPart{{
					BodyHex:  "0xdeadbeef",
					Encoding: "base64",
				}},
			},
		},
		{
			"quoted-printable",
			&scenario.MultipartBody{
				Parts: []scenario.MultipartPart{{
					Body:     "café",
					Encoding: "quoted-printable",
				}},
			},
		},
		{
			"7bit 恒等编码",
			&scenario.MultipartBody{
				Parts: []scenario.MultipartPart{{
					Body:     "ascii body",
					Encoding: "7bit",
				}},
			},
		},
		{
			"8bit 恒等编码",
			&scenario.MultipartBody{
				Parts: []scenario.MultipartPart{{
					Body:     "café 高位字节",
					Encoding: "8bit",
				}},
			},
		},
		{
			"binary 恒等编码",
			&scenario.MultipartBody{
				Parts: []scenario.MultipartPart{{
					BodyHex:  "0x00ff0102",
					Encoding: "binary",
				}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := scenario.Validate(&scenario.Scenario{
				LinkType: "ethernet",
				Packets: []scenario.Packet{{
					Stack: []scenario.Layer{
						{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
						{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
						{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 80}},
						{Type: "http_request", Fields: multipartHTTPReq(tc.m)},
					},
				}},
			}); err != nil {
				t.Fatalf("期望通过,得到错误: %v", err)
			}
		})
	}
}

func TestValidateMultipart_Errors(t *testing.T) {
	cases := []struct {
		name    string
		m       *scenario.MultipartBody
		wantSub string
	}{
		{
			"parts 为空",
			&scenario.MultipartBody{Parts: nil},
			"parts",
		},
		{
			"body 与 body_hex 同设",
			&scenario.MultipartBody{Parts: []scenario.MultipartPart{{Body: "a", BodyHex: "0x01"}}},
			"body 与 body_hex",
		},
		{
			"body_hex 非法",
			&scenario.MultipartBody{Parts: []scenario.MultipartPart{{BodyHex: "nope"}}},
			"body_hex",
		},
		{
			"encoding 非法",
			&scenario.MultipartBody{Parts: []scenario.MultipartPart{{Body: "x", Encoding: "uuencode"}}},
			"encoding",
		},
		{
			"boundary 太长(>70)",
			&scenario.MultipartBody{Boundary: strings.Repeat("a", 71), Parts: []scenario.MultipartPart{{Body: "x"}}},
			"长度",
		},
		{
			"boundary 空格结尾",
			&scenario.MultipartBody{Boundary: "abc ", Parts: []scenario.MultipartPart{{Body: "x"}}},
			"非法字符",
		},
		{
			"boundary 含非法字符",
			&scenario.MultipartBody{Boundary: "abc;def", Parts: []scenario.MultipartPart{{Body: "x"}}},
			"非法字符",
		},
		{
			"boundary 空串长度(经校验前被默认值替换,应通过)",
			&scenario.MultipartBody{Boundary: "", Parts: []scenario.MultipartPart{{Body: "x"}}},
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := scenario.Validate(&scenario.Scenario{
				LinkType: "ethernet",
				Packets: []scenario.Packet{{
					Stack: []scenario.Layer{
						{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
						{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
						{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 80}},
						{Type: "http_request", Fields: multipartHTTPReq(tc.m)},
					},
				}},
			})
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("期望通过(空 boundary 用默认值),得到错误: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("期望错误含 %q,得到 nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("错误 %q 不含 %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestValidateMultipart_BoundaryBchars 覆盖 RFC 2046 bchars 字符集边界:
// 合法 bcharsnospace 全集通过、空格仅在非末位合法。
func TestValidateMultipart_BoundaryBchars(t *testing.T) {
	legal := []string{
		"0123456789",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"abcdefghijklmnopqrstuvwxyz",
		"'()+_,.-/:=?",
		"a b c",             // 空格在中间合法
		"----=_pMaker_0001", // 默认值
	}
	illegal := []string{
		"a;b",                   // 分号不在 bchars
		"a@b",                   // @ 不在 bchars
		"a!b",                   // ! 不在 bchars
		"a*b",                   // * 不在 bchars
		"ab ",                   // 空格结尾
		strings.Repeat("a", 71), // 太长
	}
	for _, b := range legal {
		if err := scenario.Validate(&scenario.Scenario{
			LinkType: "ethernet",
			Packets: []scenario.Packet{{
				Stack: []scenario.Layer{
					{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
					{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
					{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 80}},
					{Type: "http_request", Fields: multipartHTTPReq(&scenario.MultipartBody{
						Boundary: b,
						Parts:    []scenario.MultipartPart{{Body: "x"}},
					})},
				},
			}},
		}); err != nil {
			t.Errorf("合法 boundary %q 期望通过,得到错误: %v", b, err)
		}
	}
	for _, b := range illegal {
		err := scenario.Validate(&scenario.Scenario{
			LinkType: "ethernet",
			Packets: []scenario.Packet{{
				Stack: []scenario.Layer{
					{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
					{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
					{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 80}},
					{Type: "http_request", Fields: multipartHTTPReq(&scenario.MultipartBody{
						Boundary: b,
						Parts:    []scenario.MultipartPart{{Body: "x"}},
					})},
				},
			}},
		})
		if err == nil {
			t.Errorf("非法 boundary %q 期望报错,得到 nil", b)
		}
	}
}

// TestValidateMultipart_MutexWithBody 断言 multipart 与字面 body 互斥(HTTP 与 EML)。
func TestValidateMultipart_MutexWithBody(t *testing.T) {
	// HTTP: body + multipart
	httpReq := &scenario.HTTPReqFields{Body: "x", Multipart: &scenario.MultipartBody{
		Parts: []scenario.MultipartPart{{Body: "y"}},
	}}
	err := scenario.Validate(&scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 80}},
				{Type: "http_request", Fields: httpReq},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "multipart 与 body") {
		t.Errorf("HTTP body+multipart 期望互斥报错,得到 %v", err)
	}

	// EML: body + multipart
	eml := &scenario.EMLDataFields{
		Headers:   scenario.HeaderMap{{Key: "Subject", Value: "t"}},
		Body:      "x",
		Multipart: &scenario.MultipartBody{Parts: []scenario.MultipartPart{{Body: "y"}}},
	}
	err = scenario.Validate(&scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 25}},
				{Type: "eml_data", Fields: eml},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "multipart 与 body") {
		t.Errorf("EML body+multipart 期望互斥报错,得到 %v", err)
	}
}

// TestValidateEMLData_PureMultipart 验证纯 multipart 邮件(顶层 MIME 头 + multipart、body 为空)
// 不被误拒(validateEMLDataFields 模式判定已纳入 multipart)。
func TestValidateEMLData_PureMultipart(t *testing.T) {
	eml := &scenario.EMLDataFields{
		Headers: scenario.HeaderMap{
			{Key: "From", Value: "a@b"},
			{Key: "MIME-Version", Value: "1.0"},
			{Key: "Content-Type", Value: "multipart/mixed; boundary=----=_pMaker_0001"},
		},
		Multipart: &scenario.MultipartBody{
			Parts: []scenario.MultipartPart{{Body: "part body"}},
		},
	}
	if err := scenario.Validate(&scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 25}},
				{Type: "eml_data", Fields: eml},
			},
		}},
	}); err != nil {
		t.Fatalf("纯 multipart 邮件不应被误拒: %v", err)
	}
}

// TestValidateEMLData_MultipartMutexWithRaw 断言 multipart 与 raw/raw_hex 互斥。
func TestValidateEMLData_MultipartMutexWithRaw(t *testing.T) {
	eml := &scenario.EMLDataFields{
		Raw:       "raw bytes",
		Multipart: &scenario.MultipartBody{Parts: []scenario.MultipartPart{{Body: "y"}}},
	}
	err := scenario.Validate(&scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 25}},
				{Type: "eml_data", Fields: eml},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "互斥") {
		t.Errorf("multipart+raw 期望互斥报错,得到 %v", err)
	}
}

// TestMultipartConsistencyWarnings 覆盖 boundary / CTE 一致性告警。
func TestMultipartConsistencyWarnings(t *testing.T) {
	mkScenario := func(req *scenario.HTTPReqFields) *scenario.Scenario {
		return &scenario.Scenario{
			LinkType: "ethernet",
			Packets: []scenario.Packet{{
				Stack: []scenario.Layer{
					{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
					{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
					{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 80}},
					{Type: "http_request", Fields: req},
				},
			}},
		}
	}
	wantWarn := func(t *testing.T, s *scenario.Scenario, sub string) {
		t.Helper()
		ws := scenario.Warnings(s)
		for _, w := range ws {
			if strings.Contains(w.Message, sub) {
				return
			}
		}
		t.Errorf("告警中未找到含 %q 的条目,得到 %v", sub, ws)
	}
	wantNoWarn := func(t *testing.T, s *scenario.Scenario, sub string) {
		t.Helper()
		ws := scenario.Warnings(s)
		for _, w := range ws {
			if strings.Contains(w.Message, sub) {
				t.Errorf("不期望出现含 %q 的告警,得到 %v", sub, ws)
			}
		}
	}

	// boundary 一致:无告警
	t.Run("boundary 一致", func(t *testing.T) {
		req := multipartHTTPReq(&scenario.MultipartBody{
			Boundary: "----=_pMaker_0001",
			Parts:    []scenario.MultipartPart{{Body: "x"}},
		})
		wantNoWarn(t, mkScenario(req), "boundary")
	})

	// boundary 不一致
	t.Run("boundary 不一致", func(t *testing.T) {
		req := &scenario.HTTPReqFields{
			Headers: scenario.HeaderMap{{Key: "Content-Type", Value: "multipart/form-data; boundary=wrong-boundary"}},
			Multipart: &scenario.MultipartBody{
				Boundary: "----=_pMaker_0001",
				Parts:    []scenario.MultipartPart{{Body: "x"}},
			},
		}
		wantWarn(t, mkScenario(req), "不一致")
	})

	// 缺 Content-Type 头
	t.Run("缺 Content-Type", func(t *testing.T) {
		req := &scenario.HTTPReqFields{
			Multipart: &scenario.MultipartBody{
				Parts: []scenario.MultipartPart{{Body: "x"}},
			},
		}
		wantWarn(t, mkScenario(req), "缺 Content-Type")
	})

	// CTE 不符
	t.Run("CTE 不符", func(t *testing.T) {
		req := multipartHTTPReq(&scenario.MultipartBody{
			Parts: []scenario.MultipartPart{{
				Headers:  scenario.HeaderMap{{Key: "Content-Transfer-Encoding", Value: "7bit"}},
				Body:     "x",
				Encoding: "base64",
			}},
		})
		wantWarn(t, mkScenario(req), "不符")
	})

	// CTE 缺失
	t.Run("CTE 缺失", func(t *testing.T) {
		req := multipartHTTPReq(&scenario.MultipartBody{
			Parts: []scenario.MultipartPart{{
				Body:     "x",
				Encoding: "base64",
			}},
		})
		wantWarn(t, mkScenario(req), "缺 Content-Transfer-Encoding")
	})

	// CTE 一致:无告警
	t.Run("CTE 一致", func(t *testing.T) {
		req := multipartHTTPReq(&scenario.MultipartBody{
			Parts: []scenario.MultipartPart{{
				Headers:  scenario.HeaderMap{{Key: "Content-Transfer-Encoding", Value: "base64"}},
				Body:     "x",
				Encoding: "base64",
			}},
		})
		wantNoWarn(t, mkScenario(req), "Content-Transfer-Encoding")
	})

	// 8bit 恒等编码 CTE 一致:无告警(7bit/8bit/binary 是 RFC 2045 真实 CTE 标签,
	// 参与一致性校验,配对正确的 Content-Transfer-Encoding 头 → 不告警)。
	t.Run("8bit CTE 一致", func(t *testing.T) {
		req := multipartHTTPReq(&scenario.MultipartBody{
			Parts: []scenario.MultipartPart{{
				Headers:  scenario.HeaderMap{{Key: "Content-Transfer-Encoding", Value: "8bit"}},
				Body:     "café",
				Encoding: "8bit",
			}},
		})
		wantNoWarn(t, mkScenario(req), "Content-Transfer-Encoding")
	})

	// 8bit 恒等编码 CTE 缺失:告警(与 base64/quotted-printable 同等对待)。
	t.Run("8bit CTE 缺失", func(t *testing.T) {
		req := multipartHTTPReq(&scenario.MultipartBody{
			Parts: []scenario.MultipartPart{{
				Body:     "café",
				Encoding: "8bit",
			}},
		})
		wantWarn(t, mkScenario(req), "缺 Content-Transfer-Encoding")
	})

	// 8bit 恒等编码 CTE 不符:告警。
	t.Run("8bit CTE 不符", func(t *testing.T) {
		req := multipartHTTPReq(&scenario.MultipartBody{
			Parts: []scenario.MultipartPart{{
				Headers:  scenario.HeaderMap{{Key: "Content-Transfer-Encoding", Value: "7bit"}},
				Body:     "café",
				Encoding: "8bit",
			}},
		})
		wantWarn(t, mkScenario(req), "不符")
	})

	// binary 恒等编码 CTE 一致:无告警。
	t.Run("binary CTE 一致", func(t *testing.T) {
		req := multipartHTTPReq(&scenario.MultipartBody{
			Parts: []scenario.MultipartPart{{
				Headers:  scenario.HeaderMap{{Key: "Content-Transfer-Encoding", Value: "binary"}},
				BodyHex:  "0x00ff",
				Encoding: "binary",
			}},
		})
		wantNoWarn(t, mkScenario(req), "Content-Transfer-Encoding")
	})

	// none 不参与 CTE 校验:缺 Content-Transfer-Encoding 头 → 无 CTE 告警。
	t.Run("none 缺 CTE 头不告警", func(t *testing.T) {
		req := multipartHTTPReq(&scenario.MultipartBody{
			Parts: []scenario.MultipartPart{{
				Body:     "x",
				Encoding: "none",
			}},
		})
		wantNoWarn(t, mkScenario(req), "Content-Transfer-Encoding")
	})
}
