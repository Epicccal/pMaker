package scenario

import "fmt"

// 本文件集中 checksum 覆盖的 scenario 层逻辑:
//   - validateChecksumRange:16 位值域校验(Hex 底层是 uint32,越界会被 uint16 转换静默截断)

// validateChecksumRange 校验显式覆盖的 checksum 值域:checksum 是 16 位字段,Hex 底层是
// uint32,不加值域校验会被 builder 的 uint16 转换静默截断(等于没修)。nil 表示未覆盖,
// 直接放行(走自动计算路径)。
func validateChecksumRange(c *Hex) error {
	if c != nil && *c > 0xFFFF {
		return fmt.Errorf("checksum 超出 16 位: 0x%x", *c)
	}
	return nil
}
