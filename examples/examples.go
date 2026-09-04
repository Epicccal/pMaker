// Package examples 用 embed.FS 把仓库 examples/ 下的场景 YAML(及其 @file 引用的外部文件)
// 一并编译进二进制,让 pmaker://examples 与 pmaker://examples/{protocol}/{name} 在任何
// workdir 下都能直接读出内置示例
package examples

import "embed"

//go:embed all:*
var FS embed.FS
