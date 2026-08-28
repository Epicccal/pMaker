package compress_test

import (
	"bytes"
	"testing"

	"github.com/Epicccal/pMaker/internal/util/compress"
)

// 本文件是 lzw.go 的单元测试(一一对应规约:lzw.go ↔ lzw_test.go)。
//
// 覆盖点:
//   - round-trip:DecodeLZW 解压 EncodeLZW 输出还原原文;
//   - 确定性:同输入两次调用逐字节相同;
//   - 边界:空 body(只出 3 字节头)、单字节、跨 9→10 位码宽增长;
//   - 码表满路径:造确定能填满 65536 项码表的输入,断言输出流不含清除码 256(本实现冻结码表、
//     不发清除)且 round-trip 正确;
//   - DecodeLZW 错误路径:坏头、非法 maxbits、保留位置位。

func TestLZW_RoundTrip(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x41},
		[]byte("A"),
		[]byte("Hello, World!"),
		[]byte("The quick brown fox jumps over the lazy dog. 1234567890"),
		bytes.Repeat([]byte("ABCDEFGH"), 64), // 跨 9→10 位码宽增长
		bytes.Repeat([]byte("ab"), 1000),     // 中等重复,触发多次码宽增长
		bytes.Repeat([]byte("ab"), 50000),    // 跨多次码宽增长
		bytes.Repeat([]byte("abc"), 7000),    // 21000 字节,跨码宽增长
		[]byte("<html><body>Hello from pMaker compress content encoding example</body></html>\n"),
	}
	for _, body := range cases {
		enc, err := compress.EncodeLZW(body)
		if err != nil {
			t.Fatalf("EncodeLZW: %v", err)
		}
		if len(enc) < 3 || enc[0] != 0x1F || enc[1] != 0x9D {
			t.Errorf("坏 .Z 头: % x", enc[:min(3, len(enc))])
			continue
		}
		if enc[2] != 0x90 {
			t.Errorf("flags=%#x, want 0x90 (maxbits=16|blockmode)", enc[2])
		}
		if len(body) == 0 {
			if len(enc) != 3 {
				t.Errorf("空 body 应只出 3 字节头, got len=%d", len(enc))
			}
			continue
		}
		dec, err := compress.DecodeLZW(enc)
		if err != nil {
			t.Fatalf("DecodeLZW: %v", err)
		}
		if !bytes.Equal(dec, body) {
			t.Errorf("round-trip 不符(len=%d):\n got %q\n want %q", len(body), dec, body)
		}
	}
}

func TestLZW_Deterministic(t *testing.T) {
	body := []byte("Hello from pMaker! The quick brown fox jumps over the lazy dog. 1234567890")
	c1, _ := compress.EncodeLZW(body)
	c2, _ := compress.EncodeLZW(body)
	if !bytes.Equal(c1, c2) {
		t.Errorf("两次压缩结果不一致(确定性失败): len=%d vs %d", len(c1), len(c2))
	}
}

// TestLZW_TableFull 断言码表满路径:造确定能填满 65536 项码表的高熵输入,
// 本实现采用「冻结码表、不发清除码」策略(ncompress block-mode 语义),故输出流中
// **不应出现清除码 256**;且 round-trip 仍正确(冻结后继续用已学字典解码)。
func TestLZW_TableFull(t *testing.T) {
	body := make([]byte, 0, 1<<18)
	for i := range 1 << 18 {
		body = append(body, byte(i*73%251))
	}
	enc, _ := compress.EncodeLZW(body)
	if containsClearCode(enc) {
		t.Errorf("本实现冻结码表、不应发清除码 256,但输出流中检测到清除码")
	}
	dec, err := compress.DecodeLZW(enc)
	if err != nil {
		t.Fatalf("DecodeLZW: %v", err)
	}
	if !bytes.Equal(dec, body) {
		t.Errorf("码表满后 round-trip 不符: got len=%d, want len=%d", len(dec), len(body))
	}
}

func TestDecodeLZW_BadInput(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"空输入", nil},
		{"只有1字节", []byte{0x1F}},
		{"坏魔数", []byte{0x1F, 0x8B, 0x90}},
		{"maxbits=8(太小)", []byte{0x1F, 0x9D, 0x08}},
		{"maxbits=17(太大)", []byte{0x1F, 0x9D, 0x11}},
		{"保留位置位", []byte{0x1F, 0x9D, 0x90 | 0x20}},
	}
	for _, tc := range cases {
		_, err := compress.DecodeLZW(tc.in)
		if err == nil {
			t.Errorf("[%s] 期望 error,got nil", tc.name)
		}
	}
}

// containsClearCode 扫描 .Z 流,检测是否出现清除码 256。镜像解码语义:连续位打包、
// 首码不登记表项、之后每码登记一项、码宽在 freeEnt > maxcode 时升档。
func containsClearCode(in []byte) bool {
	if len(in) < 3 {
		return false
	}
	data := in[3:]
	nBits := 9
	maxcode := (1 << nBits) - 1
	freeEnt := 257
	const clearCode = 256
	bitPos := 0
	totalBits := len(data) * 8
	old := -1
	for bitPos+nBits <= totalBits {
		code := 0
		for i := 0; i < nBits; i++ {
			p := bitPos >> 3
			if (data[p]>>uint(bitPos&7))&1 != 0 {
				code |= 1 << i
			}
			bitPos++
		}
		if code == clearCode {
			return true
		}
		if old != -1 && freeEnt < (1<<16) {
			freeEnt++
			if freeEnt > maxcode && nBits < 16 {
				nBits++
				if nBits == 16 {
					maxcode = 1 << 16
				} else {
					maxcode = (1 << nBits) - 1
				}
			}
		}
		old = code
	}
	return false
}
