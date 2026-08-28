package builder

import (
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件仅在测试构建时编译(_test.go 后缀),把仅供测试的导出别名集中于此,
// 避免污染正式构建产物。builder_test(外部测试包,package builder_test)无法直接
// 访问未导出函数,通过这里的别名桥接。

// ApplyContentCodingsForTest 是 applyContentCodings 的测试导出别名。
func ApplyContentCodingsForTest(b []byte, list scenario.CodingList) ([]byte, error) {
	return applyContentCodings(b, list)
}

// ApplyTransferCodingsForTest 是 applyTransferCodings 的测试导出别名。
func ApplyTransferCodingsForTest(b []byte, list scenario.CodingList, opts scenario.ChunkedOptions) ([]byte, error) {
	return applyTransferCodings(b, list, opts)
}

// ApplyAutoContentLengthForTest 是 applyAutoContentLength 的测试导出别名。
func ApplyAutoContentLengthForTest(h scenario.HeaderMap, on bool, n int) scenario.HeaderMap {
	return applyAutoContentLength(h, on, n)
}
