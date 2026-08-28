package dotframe_test

import (
	"bytes"
	"testing"

	"github.com/Epicccal/pMaker/internal/util/dotframe"
)

// 本文件覆盖 dotframe 包的 RFC 5321 §4.5.2 / RFC 1939 §3 dot 成帧原语单元测试。
// 测试用例从 builder/eml_data_test.go 的 TestApplyDotStuffing /
// TestAppendDotTerminator 迁移，直接测试底层原语而非经 builder 导出别名。

func TestApplyDotStuffing(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"行首 . → ..", "Subject: t\r\n\r\n.hidden\r\nnormal\r\n", "Subject: t\r\n\r\n..hidden\r\nnormal\r\n"},
		{"行只有 . → ..", ".\r\nafter\r\n", "..\r\nafter\r\n"},
		{"无行首 . 不变", "line1\r\nline2\r\n", "line1\r\nline2\r\n"},
		{"首行行首 . 也 stuff", ".first\r\n", "..first\r\n"},
		{"裸 \\n 非 \\r\\n 边界不 stuff", "x\n.hidden\n", "x\n.hidden\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := dotframe.ApplyDotStuffing([]byte(c.in))
			if !bytes.Equal(got, []byte(c.want)) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestApplyDotStuffing_Empty(t *testing.T) {
	got := dotframe.ApplyDotStuffing(nil)
	if len(got) != 0 {
		t.Errorf("nil input: got %q, want empty", got)
	}
}

func TestApplyDotStuffing_MultipleDotLines(t *testing.T) {
	// 多行行首 . 每行都 stuff。
	in := ".line1\r\n.line2\r\nnormal\r\n.line3\r\n"
	want := "..line1\r\n..line2\r\nnormal\r\n..line3\r\n"
	got := dotframe.ApplyDotStuffing([]byte(in))
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestApplyDotStuffing_AlreadyStuffed(t *testing.T) {
	// 已经 stuff 过的 .. 行首:.. 不再变 ... (行首是 . 故再加一个 .)。
	// 若调用方传入已 stuff 过的内容再次 stuff,行为是幂等地再加一层。
	// 此用例验证实现对行首连续 . 的一致行为(仅前置一个 .)。
	in := "..already\r\n"
	want := "...already\r\n"
	got := dotframe.ApplyDotStuffing([]byte(in))
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestAppendDotTerminator(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"以 \\r\\n 结尾 → 追加 .\\r\\n", "body\r\n", "body\r\n.\r\n"},
		{"不以 \\r\\n 结尾 → 追加 \\r\\n.\\r\\n", "raw bytes", "raw bytes\r\n.\r\n"},
		{"空内容 → 追加 \\r\\n.\\r\\n", "", "\r\n.\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := dotframe.AppendDotTerminator([]byte(c.in))
			if !bytes.Equal(got, []byte(c.want)) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestAppendDotTerminator_AfterStuffing(t *testing.T) {
	// 典型用法:先 stuff 再追加终止符。
	content := ".secret\r\nnormal\r\n"
	stuffed := dotframe.ApplyDotStuffing([]byte(content))
	framed := dotframe.AppendDotTerminator(stuffed)
	want := "..secret\r\nnormal\r\n.\r\n"
	if !bytes.Equal(framed, []byte(want)) {
		t.Errorf("got %q, want %q", framed, want)
	}
}

func TestAppendDotTerminator_OnlyDotLine(t *testing.T) {
	// stuff 后的单 . 行（已变 ..）再追加终止符。
	content := dotframe.ApplyDotStuffing([]byte(".\r\n"))
	got := dotframe.AppendDotTerminator(content)
	want := "..\r\n.\r\n"
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}
