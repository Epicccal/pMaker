package scenario

import "fmt"

// 本文件集中 checksum 覆盖的 scenario 层逻辑:
//   - hasChecksumOverride:报言层是否显式写了 checksum(flow 展开器会丢弃,故需拦截)
//   - validateChecksumRange:16 位值域校验(Hex 底层是 uint32,越界会被 uint16 转换静默截断)

// hasChecksumOverride 报告该层是否显式写了 checksum 字段。flow 展开器会重建各层
// 字段结构体并丢弃 Checksum,故 flow.stack 上一旦写 checksum 即静默无效;validateFlow
// 据此先于 validateLayer 拦截并引导改用 standalone packet。
//
// IPv6 头部没有 Checksum 字段
func hasChecksumOverride(l Layer) bool {
	switch f := l.Fields.(type) {
	case *IPv4Fields:
		return f.Checksum != nil
	case *TCPFields:
		return f.Checksum != nil
	case *UDPFields:
		return f.Checksum != nil
	case *ICMPFields:
		return f.Checksum != nil
	case *ICMPv6Fields:
		return f.Checksum != nil
	}
	return false
}

// validateChecksumRange 校验显式覆盖的 checksum 值域:checksum 是 16 位字段,Hex 底层是
// uint32,不加值域校验会被 builder 的 uint16 转换静默截断(等于没修)。nil 表示未覆盖,
// 直接放行(走自动计算路径)。
func validateChecksumRange(c *Hex) error {
	if c != nil && *c > 0xFFFF {
		return fmt.Errorf("checksum 超出 16 位: 0x%x", *c)
	}
	return nil
}
