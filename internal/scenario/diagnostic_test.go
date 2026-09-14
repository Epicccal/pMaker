package scenario_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件是「internal/ 禁止 slog 打用户可见诊断」的守卫测试(设计说明见 diagnostic.go):
// 日志不回流调用方,MCP(stdio) 下 stdout 是 JSON-RPC 帧、stderr 的日志模型看不到,
// 告警走日志等于加在死路上。软告警的唯一出口是 []Diagnostic 经 scenario.Warnings 回流
// (CLI 渲染 stderr 文本、MCP 渲染结构化 warnings)。
//
// internal/ 库代码无任何日志需求(CLI/MCP 入口在 cmd/ 层,进度日志在那里用 slog 打 stderr);
// 将来若出现 internal/ 内的调试日志需求,应先考虑能否用 Diagnostic/软告警表达,
// 确需日志再收窄本守卫的豁免范围并说明理由。

// TestInternalNoSlog 扫描 internal/ 全部非测试 .go 源文件,出现 slog 引用即失败。
func TestInternalNoSlog(t *testing.T) {
	root := ".." // 测试工作目录是 internal/scenario,扫整个 internal/
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// 跳过测试数据与 vendor 类目录(无 Go 源)。
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		t.Fatalf("扫描 internal/ 失败: %v", err)
	}

	var offenders []string
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", path, err)
		}
		src := string(data)
		if strings.Contains(src, "log/slog") || strings.Contains(src, "slog.") {
			offenders = append(offenders, path)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("internal/ 内禁止用 slog 打用户可见诊断(日志不回流调用方,MCP 下模型永远看不到):\n%s\n软告警一律经 scenario.Diagnostic / Warnings 回流;进度/调试日志放 cmd/ 层",
			strings.Join(offenders, "\n"))
	}
}
