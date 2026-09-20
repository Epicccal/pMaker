// Command pmaker-mcp 把 pMaker 的核心能力(生成场景 YAML、生成 pcap)暴露成 MCP server,
// 供支持 MCP 的客户端(其他大模型)调用。走 stdio transport。
//
// 用法:
//
//	pmaker-mcp -workdir <场景工作目录>
//	# 或环境变量 PMAKER_WORKDIR(缺省 = 当前工作目录)
//
// workdir 下自动创建 yaml/、pcap/ 两个子目录,分别存放 generate_yaml / generate_pcap 的产物。
// 复用 internal/scenario|plan|builder|writer 现有链路,不改动 CLI 行为。
// 详见仓库根 CLAUDE.md。
package main

import (
	"embed"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/server"
)

// version 由构建时 -ldflags 注入,默认 "dev"。
var version = "dev"

// 通配 `all:` 前缀不可省:裸 `//go:embed resources/schema` 会静默跳过 `_` / `.` 开头的文件,
// 而 `_conventions.md`、`_why_*.md` 正是这种命名(下划线前缀标记「非层文档」)。
// 少了它,pmaker://schema/_conventions 会在运行期 404 而编译期无任何提示。
//
//go:embed all:resources/schema
var schemaFS embed.FS

const schemaMIME = "text/markdown"

func main() {
	if err := run(os.Args[1:], os.Getenv, func(srv *server.MCPServer) error {
		return server.ServeStdio(srv)
	}); err != nil {
		fmt.Fprintln(os.Stderr, "pmaker-mcp:", err)
		os.Exit(1)
	}
}

// run 是 main 的可测核心:解析 flag、建子目录、注册 tool/resource、起 server。
// 把 flag 集、env 读取、serve 拆成入参,使 workdir 解析与 MkdirAll 等分支可在不触
// os.Exit、不真正起 stdio 的前提下被测试覆盖;main 仅做错误打印 + 退出码。
func run(args []string, getenv func(string) string, serve func(*server.MCPServer) error) error {
	fs := flag.NewFlagSet("pmaker-mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workdir := fs.String("workdir", envOr("PMAKER_WORKDIR", "", getenv), "场景工作目录(@file 相对路径相对它解析;其下自动建 yaml/ pcap/ 子目录存放生成产物)")
	if err := fs.Parse(args); err != nil {
		// -h/-help:flag 打印 usage 后返回 ErrHelp,视为正常退出(与默认 flag 集的
		// ExitOnError 语义中 help 退出码 0 对齐),供冒烟测试 ./bin/pmaker-mcp -h 通过。
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	if *workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("获取工作目录: %w", err)
		}
		*workdir = wd
	}
	// 解析为绝对路径(输出路径校验、摘要里都好引用)。
	absWorkdir, err := filepath.Abs(*workdir)
	if err != nil {
		return fmt.Errorf("解析 workdir: %w", err)
	}
	// 在 workdir 下自动建 yaml/、pcap/ 两个子目录,分别存放 generate_yaml / generate_pcap 的产物。
	yamlDir := filepath.Join(absWorkdir, "yaml")
	pcapDir := filepath.Join(absWorkdir, "pcap")
	for _, d := range []string{yamlDir, pcapDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return fmt.Errorf("创建目录 %s: %w", d, err)
		}
	}

	cfg := config{workdir: absWorkdir, yamlDir: yamlDir, pcapDir: pcapDir}

	srv := server.NewMCPServer("pmaker-mcp", version,
		server.WithToolCapabilities(true),
		// subscribe=false(不支持资源订阅);listChanged=false:资源在启动时一次性注册,
		// 运行期不变,不发送 notifications/resources/list_changed。
		server.WithResourceCapabilities(false, false),
	)
	srv.AddTool(generateYAMLTool(), cfg.handleGenerateYAML)
	srv.AddTool(generatePcapTool(), cfg.handleGeneratePcap)
	cfg.registerResources(srv)

	return serve(srv)
}

// envOr 返回环境变量值,空则返回 fallback。getenv 注入便于测试(默认传 os.Getenv)。
func envOr(key, fallback string, getenv func(string) string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

// config 在 server 生命周期内不变,作为 handler 的闭包状态。
type config struct {
	workdir string // @file 相对路径的基准目录;其下有 yaml/ pcap/ 子目录
	yamlDir string // generate_yaml 产物落盘目录(= workdir/yaml,绝对路径)
	pcapDir string // generate_pcap 产物落盘目录(= workdir/pcap,绝对路径)
}
