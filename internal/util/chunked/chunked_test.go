package chunked_test

import (
	"testing"

	"github.com/Epicccal/pMaker/internal/util/chunked"
)

// 本文件覆盖 chunked 包的 RFC 9112 §7.1 chunked transfer-encoding 成帧单元测试。
// 测试用例从 builder/http_coding_test.go 的 TestChunkedFrame_* 系列迁移，
// 直接测试底层 chunked.Frame 原语而非经 builder 导出别名。

func TestFrame_WholeOneChunk(t *testing.T) {
	// size<=0：整段一块。
	body := []byte("hello world")
	got := chunked.Frame(body, 0)
	want := "b\r\nhello world\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("整段一块 got %q, want %q", got, want)
	}
}

func TestFrame_MultiChunk(t *testing.T) {
	// size=4：切多块，块长十六进制。
	body := []byte("hello world!") // 12 字节
	got := chunked.Frame(body, 4)
	want := "4\r\nhell\r\n4\r\no wo\r\n4\r\nrld!\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("切多块 got %q, want %q", got, want)
	}
}

func TestFrame_EmptyBody(t *testing.T) {
	// 空 body：仅终止块。
	got := chunked.Frame(nil, 0)
	want := "0\r\n\r\n"
	if string(got) != want {
		t.Errorf("空 body got %q, want %q", got, want)
	}
}

func TestFrame_DefaultSizeWholeChunk(t *testing.T) {
	// size==0：整段一块（契约行为）。size<0 是 scenario 校验硬错，不应到达此处，
	// 故只测合法的 size==0，不把非法负数路径当作等价语义固化。
	body := []byte("xyz")
	got := chunked.Frame(body, 0)
	want := "3\r\nxyz\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("size=0 整段一块 got %q, want %q", got, want)
	}
}

func TestFrame_SizeLargerThanBody(t *testing.T) {
	// size 大于 body 长度：单块，块长 == body 实际长度（不按 size 截断出空块）。
	body := []byte("short") // 5 字节
	got := chunked.Frame(body, 100)
	want := "5\r\nshort\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("size>len got %q, want %q（应为单块，块长=body 长度）", got, want)
	}
}

func TestFrame_NonDivisibleRemainder(t *testing.T) {
	// size 不能整除：最后一块为余数，块长反映实际剩余字节。
	body := []byte("hello world!") // 12 字节，size=5 -> 5+5+2
	got := chunked.Frame(body, 5)
	want := "5\r\nhello\r\n5\r\n worl\r\n2\r\nd!\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("非整除余数 got %q, want %q（最后一块应为 2 字节）", got, want)
	}
}

func TestFrame_SingleByteChunks(t *testing.T) {
	// size=1：每字节一块，验证极小切分。
	body := []byte("abc")
	got := chunked.Frame(body, 1)
	want := "1\r\na\r\n1\r\nb\r\n1\r\nc\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("单字节块 got %q, want %q", got, want)
	}
}

func TestFrame_EmptySlice(t *testing.T) {
	// 空切片（非 nil）与 nil 行为一致：仅终止块。
	got := chunked.Frame([]byte{}, 0)
	want := "0\r\n\r\n"
	if string(got) != want {
		t.Errorf("空切片 got %q, want %q", got, want)
	}
}

func TestFrame_ChunkLengthIsHex(t *testing.T) {
	// 块长必须是十六进制（小写）。16 字节块长应为 "10"（不是 "16"）。
	body := make([]byte, 16)
	for i := range body {
		body[i] = 'x'
	}
	got := chunked.Frame(body, 0)
	want := "10\r\n" + string(body) + "\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("16 字节块长应为 hex 10，got %q, want %q", got, want)
	}
}
