package scenario

import (
	"testing"
)

// 本文件针对 ftp_consistency.go 里几条协商文本解析正则/函数,验证提取有效性:
// 每条正则各配 2 个用例(正例命中 + 反例不命中)。
//   - ftpPortTupleRegex(已存在,但这里补单元测试):带括号六元组
//   - epsvTupleRegex:229 响应 (|||port|)
//   - eprtArgsRegex:EPRT 请求 |netproto|addr|port|
//
// parseFTPPortTuple / parseEPSVTuple / parseEPRTArgs 是各自正则的语义化封装,
// 直接调用它们即可覆盖正则命中/不命中两条路径。

// --- ftpPortTupleRegex(227/PORT 六元组)---

func TestParseFTPPortTuple_Hit(t *testing.T) {
	// 正例:带括号的 227 文本,六元组 10,0,0,21,195,80 → 10.0.0.21:50000
	ip, port, ok := parseFTPPortTuple("Entering Passive Mode (10,0,0,21,195,80).")
	if !ok {
		t.Fatal("期望解析成功")
	}
	if ip != "10.0.0.21" || port != 50000 {
		t.Fatalf("得到 %s:%d,期望 10.0.0.21:50000", ip, port)
	}
}

func TestParseFTPPortTuple_Miss(t *testing.T) {
	// 反例:无括号、非六元组("PORT 10,0,0,10" 只有 4 段)→ 不命中。
	if _, _, ok := parseFTPPortTuple("PORT 10,0,0,10"); ok {
		t.Fatal("非六元组不应命中")
	}
}

// --- portArgsRegex(PORT 裸六元组,无括号、整串)---

func TestParseFTPPortTuple_BareHit(t *testing.T) {
	// 正例:裸六元组(PORT args 字段形式)→ ftpPortTupleRegex 不中,回退 portArgsRegex 命中。
	ip, port, ok := parseFTPPortTuple("10,0,0,10,192,5")
	if !ok {
		t.Fatal("裸六元组应回退命中 portArgsRegex")
	}
	if ip != "10.0.0.10" || port != 49157 {
		t.Fatalf("得到 %s:%d,期望 10.0.0.10:49157", ip, port)
	}
}

func TestParseFTPPortTuple_BareMiss(t *testing.T) {
	// 反例:裸串带括号外的杂字("x10,0,0,10,192,5")→ portArgsRegex 锚定 ^ 故不命中。
	if _, _, ok := parseFTPPortTuple("x10,0,0,10,192,5"); ok {
		t.Fatal("带前缀杂字的裸串不应命中 portArgsRegex")
	}
}

// --- epsvTupleRegex(229 EPSV)---

func TestParseEPSVTuple_Hit(t *testing.T) {
	// 正例:标准 229 文本 (|||50000|) → 端口 50000,无地址。
	port, ok := parseEPSVTuple("Entering Extended Passive Mode (|||50000|).")
	if !ok {
		t.Fatal("期望解析成功")
	}
	if port != 50000 {
		t.Fatalf("得到端口 %d,期望 50000", port)
	}
}

func TestParseEPSVTuple_Miss(t *testing.T) {
	// 反例:缺少扩展分隔符的括号(普通圆括号包数字)→ 不命中。
	if _, ok := parseEPSVTuple("Entering Passive Mode (50000)."); ok {
		t.Fatal("非 (|||port|) 格式不应命中")
	}
}

// --- eprtArgsRegex(EPRT)---

func TestParseEPRTArgs_Hit(t *testing.T) {
	// 正例:|2|2001:db8::10|49157| → IPv6 地址 + 端口 49157。
	ip, port, ok := parseEPRTArgs("|2|2001:db8::10|49157|")
	if !ok {
		t.Fatal("期望解析成功")
	}
	if ip != "2001:db8::10" || port != 49157 {
		t.Fatalf("得到 %s:%d,期望 2001:db8::10:49157", ip, port)
	}
}

func TestParseEPRTArgs_Miss(t *testing.T) {
	// 反例:netproto=3(非 1/2)→ 地址族不匹配,解析失败。
	if _, _, ok := parseEPRTArgs("|3|2001:db8::10|49157|"); ok {
		t.Fatal("非法 netproto=3 不应命中")
	}
}
