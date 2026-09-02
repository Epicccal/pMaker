package crlf

import "testing"

// 本文件覆盖 NormalizeCRLF 原语：裸 \n → \r\n，已是 \r\n 与 lone \r 不动，无 \n 原样返回。

func TestNormalizeCRLF_NoLF(t *testing.T) {
	if got := NormalizeCRLF("abc"); got != "abc" {
		t.Errorf("无 \\n 应原样返回, got %q", got)
	}
}

func TestNormalizeCRLF_BareLF_Normalized(t *testing.T) {
	// 裸 \n → \r\n（行中、行尾均归一化）。
	if got := NormalizeCRLF("a\nb\n"); got != "a\r\nb\r\n" {
		t.Errorf("裸 \\n 应归一化为 \\r\\n, got %q", got)
	}
}

func TestNormalizeCRLF_CRLF_Unchanged(t *testing.T) {
	// 已是 \r\n 不动。
	if got := NormalizeCRLF("a\r\nb\r\n"); got != "a\r\nb\r\n" {
		t.Errorf("已是 \\r\\n 不应变, got %q", got)
	}
}

func TestNormalizeCRLF_MixedLF_Normalized(t *testing.T) {
	// 混合：\r\n 与裸 \n 共存，只归一化裸 \n。
	if got := NormalizeCRLF("a\r\nb\nc\n"); got != "a\r\nb\r\nc\r\n" {
		t.Errorf("混合换行只归一化裸 \\n, got %q", got)
	}
}

func TestNormalizeCRLF_LeadingBareLF(t *testing.T) {
	// 行首裸 \n（i==0，无前一字符）→ \r\n。
	if got := NormalizeCRLF("\nfirst"); got != "\r\nfirst" {
		t.Errorf("行首裸 \\n 应归一化, got %q", got)
	}
}

func TestNormalizeCRLF_LoneCR_Unchanged(t *testing.T) {
	// lone \r（后非 \n）不动，避免改变二进制语义。
	if got := NormalizeCRLF("a\rb\r\n"); got != "a\rb\r\n" {
		t.Errorf("lone \\r 不应变, got %q", got)
	}
}

func TestNormalizeCRLF_CRBeforeLF_Preserved(t *testing.T) {
	// \r\n 中 \n 的前一字符是 \r，不重复插入 \r。
	if got := NormalizeCRLF("\r\n"); got != "\r\n" {
		t.Errorf("\\r\\n 应保持不变, got %q", got)
	}
}

func TestNormalizeCRLF_Empty(t *testing.T) {
	if got := NormalizeCRLF(""); got != "" {
		t.Errorf("空串应原样返回, got %q", got)
	}
}
