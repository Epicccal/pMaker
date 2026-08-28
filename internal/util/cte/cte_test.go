package cte_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/util/cte"
)

// 本文件覆盖 cte 包的 RFC 2045 CTE 原语单元测试。
// base64 折行测试从 builder/multipart_test.go 的 TestSerializeMultipart_Base64Fold 迁移，
// QP 编码测试从 TestSerializeMultipart_QuotedPrintable 迁移，直接测试底层原语。

// ---- Base64Fold ----

func TestBase64Fold_ShortBody(t *testing.T) {
	// 短内容 ≤76 字符 → 单行，无折行符。
	body := []byte("hello")
	got := cte.Base64Fold(body)
	want := base64.StdEncoding.EncodeToString(body)
	if string(got) != want {
		t.Errorf("短内容 got %q, want %q", got, want)
	}
}

func TestBase64Fold_LongBody_LineFold(t *testing.T) {
	// 200 字节 → base64 约 268 字符，每行 ≤76 字符，\r\n 分隔。
	body := []byte(strings.Repeat("A", 200))
	got := cte.Base64Fold(body)
	for _, line := range strings.Split(string(got), "\r\n") {
		if len(line) > 76 {
			t.Errorf("折行后某行 %d 字符 > 76: %q", len(line), line)
		}
	}
}

func TestBase64Fold_LongBody_RoundTrip(t *testing.T) {
	// 编码后去折行符可还原原始 body（完整性）。
	body := []byte(strings.Repeat("A", 200))
	got := cte.Base64Fold(body)
	encStr := strings.ReplaceAll(string(got), "\r\n", "")
	dec, err := base64.StdEncoding.DecodeString(encStr)
	if err != nil {
		t.Fatalf("base64 解码失败: %v", err)
	}
	if string(dec) != string(body) {
		t.Errorf("base64 往返不一致")
	}
}

func TestBase64Fold_Exactly76Chars(t *testing.T) {
	// 编码后恰好 76 字符：单行，无 \r\n。
	// 57 字节 → base64 = 76 字符（57 * 4 / 3 = 76）。
	body := make([]byte, 57)
	for i := range body {
		body[i] = byte(i)
	}
	got := cte.Base64Fold(body)
	if strings.Contains(string(got), "\r\n") {
		t.Errorf("恰好 76 字符不应折行，got %q", got)
	}
	if len(got) != 76 {
		t.Errorf("长度应为 76，got %d", len(got))
	}
}

func TestBase64Fold_MoreThan76Chars(t *testing.T) {
	// 编码后超过 76 字符：必须有 \r\n 折行符。
	body := make([]byte, 58) // 58 字节 → 80 字符
	got := cte.Base64Fold(body)
	if !strings.Contains(string(got), "\r\n") {
		t.Errorf(">76 字符应折行，got %q", got)
	}
}

func TestBase64Fold_EmptyBody(t *testing.T) {
	// 空 body → 空输出（base64 编码空字节 = ""）。
	got := cte.Base64Fold(nil)
	if len(got) != 0 {
		t.Errorf("空 body got %q, want empty", got)
	}
}

func TestBase64Fold_Deterministic(t *testing.T) {
	// 同输入两次调用产出逐字节相同输出（确定性）。
	body := []byte("deterministic content 12345")
	a := cte.Base64Fold(body)
	b := cte.Base64Fold(body)
	if string(a) != string(b) {
		t.Errorf("非确定性：第一次 %q，第二次 %q", a, b)
	}
}

// ---- QPEncode ----

func TestQPEncode_ASCIIPassthrough(t *testing.T) {
	// 纯 ASCII 可打印字符原样透传（无 = 转义）。
	body := []byte("hello world")
	got, err := cte.QPEncode(body)
	if err != nil {
		t.Fatalf("QPEncode: %v", err)
	}
	if string(got) != "hello world" {
		t.Errorf("got %q, want %q", got, "hello world")
	}
}

func TestQPEncode_NonASCII(t *testing.T) {
	// é (U+00E9) UTF-8 = 0xC3 0xA9 → QP =C3=A9。
	body := []byte("café")
	got, err := cte.QPEncode(body)
	if err != nil {
		t.Fatalf("QPEncode: %v", err)
	}
	if !strings.Contains(string(got), "=C3=A9") {
		t.Errorf("é 应编码为 =C3=A9，got %q", got)
	}
}

func TestQPEncode_EqualsSign(t *testing.T) {
	// '=' → =3D（QP 转义字符本身）。
	body := []byte("a=b")
	got, err := cte.QPEncode(body)
	if err != nil {
		t.Fatalf("QPEncode: %v", err)
	}
	if !strings.Contains(string(got), "=3D") {
		t.Errorf("= 应编码为 =3D，got %q", got)
	}
}

func TestQPEncode_MixedContent(t *testing.T) {
	// 混合内容：café = test → caf=C3=A9 =3D test。
	body := []byte("café = test")
	got, err := cte.QPEncode(body)
	if err != nil {
		t.Fatalf("QPEncode: %v", err)
	}
	want := "caf=C3=A9 =3D test"
	if !strings.Contains(string(got), want) {
		t.Errorf("got %q, 期望含 %q", got, want)
	}
}

func TestQPEncode_EmptyBody(t *testing.T) {
	// 空 body → 空输出。
	got, err := cte.QPEncode(nil)
	if err != nil {
		t.Fatalf("QPEncode: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("空 body got %q, want empty", got)
	}
}

func TestQPEncode_Deterministic(t *testing.T) {
	// 同输入两次产出相同（确定性）。
	body := []byte("café = test 12345")
	a, err := cte.QPEncode(body)
	if err != nil {
		t.Fatalf("QPEncode: %v", err)
	}
	b, err := cte.QPEncode(body)
	if err != nil {
		t.Fatalf("QPEncode: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("非确定性：第一次 %q，第二次 %q", a, b)
	}
}
