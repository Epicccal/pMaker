package builder

import (
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件仅在测试构建时编译(_test.go 后缀),把仅供测试的导出别名集中于此,
// 避免污染正式构建产物。builder_test(外部测试包,package builder_test)无法直接
// 访问未导出函数,通过这里的别名桥接。

// CompressLZWForTest 是 compressLZW 的测试导出别名。
// 专为 LZW 原语边界测试(码表满/相位补齐/空 body/跨码宽增长),HTTP 接线路径走
// ApplyContentCodingsForTest(CodingCompress) 间接覆盖。
func CompressLZWForTest(b []byte) ([]byte, error) { return compressLZW(b) }

// ApplyContentCodingsForTest 是 applyContentCodings 的测试导出别名。
func ApplyContentCodingsForTest(b []byte, list scenario.CodingList) ([]byte, error) {
	return applyContentCodings(b, list)
}

// ApplyTransferCodingsForTest 是 applyTransferCodings 的测试导出别名。
func ApplyTransferCodingsForTest(b []byte, list scenario.CodingList, opts scenario.ChunkedOptions) ([]byte, error) {
	return applyTransferCodings(b, list, opts)
}

// ChunkedFrameForTest 是 chunkedFrame 的测试导出别名。
func ChunkedFrameForTest(b []byte, size int) []byte {
	return chunkedFrame(b, size)
}

// ApplyAutoContentLengthForTest 是 applyAutoContentLength 的测试导出别名。
func ApplyAutoContentLengthForTest(h scenario.HeaderMap, on bool, n int) scenario.HeaderMap {
	return applyAutoContentLength(h, on, n)
}
