package scenario

// 本文件仅在测试构建时编译(_test.go 后缀),把仅供测试的导出别名集中于此,
// 避免污染正式构建产物。scenario_test(外部测试包,package scenario_test)无法直接
// 访问未导出函数,通过这里的别名桥接。

// MaxChunkedSize 是 maxChunkedSize 的测试导出别名。
// 供 http_validate_test.go 校验超限边界用例。
const MaxChunkedSize = maxChunkedSize

// IMAPLiteralEMLBytesForTest 是 imapLiteralEMLBytes 的测试导出别名。
// 供跨包等价测试断言其与 builder 的 eml_data 内容口径逐字节一致
// (internal/scenario/imap_consistency_test.go 的 TestIMAPLiteralEMLBytes_EquivToBuilder)。
func IMAPLiteralEMLBytesForTest(f *EMLDataFields) ([]byte, bool) {
	return imapLiteralEMLBytes(f)
}
