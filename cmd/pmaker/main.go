// Command pmaker 从声明式场景文件(YAML)生成 pcap,
// 用声明式场景文件(YAML)构造可复现的离线流量样本,让验证流量像代码一样可读、可审、可回归。设计见仓库根目录 CLAUDE.md。
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/summary"
	"github.com/Epicccal/pMaker/internal/writer"
)

// version 由构建时 -ldflags 注入,默认 "dev"。
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "gen":
		os.Exit(cmdGen(os.Args[2:]))
	case "validate":
		os.Exit(cmdValidate(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("pmaker", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知命令 %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `pmaker — 从声明式场景文件生成 pcap

用法:
  pmaker gen      -f <scenario.yaml> -o <out.pcap>   从场景文件生成 pcap
  pmaker validate -f <scenario.yaml>                 校验场景文件
  pmaker version                                     打印版本
`)
}

// parseFlags 解析子命令 flag,返回 (退出码, 是否继续执行)。
// 子命令 FlagSet 一律用 ContinueOnError 而非 ExitOnError:后者在 flag 出错时直接
// os.Exit(2),会把进程内调用 cmdGen/cmdValidate 的单测二进制一起带走(与
// cmd/pmaker-mcp 的 run 同一考量)。-h/-help 时 flag 已打印用法并返回 ErrHelp,
// 视为正常退出(退出码 0);其余解析错误 flag 已打印到 stderr,返回用法错误码 2。
func parseFlags(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, false
		}
		return 2, false
	}
	return 0, true
}

// cmdGen 串接:Load -> Validate -> plan.Plan(汇流+排序)-> BuildPlanned -> Write。
func cmdGen(args []string) int {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("f", "", "输入场景文件 (YAML)")
	out := fs.String("o", "", "输出 pcap 文件")
	if rc, ok := parseFlags(fs, args); !ok {
		return rc
	}

	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "gen: 需要 -f <scenario> 与 -o <out.pcap>")
		return 2
	}

	s, err := scenario.Load(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		return 1
	}
	if err := scenario.Validate(s); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		return 1
	}
	for _, w := range scenario.Warnings(s) {
		fmt.Fprintf(os.Stderr, "warn: [%s] %s\n", w.Code, w.Message)
	}
	// packets 与 flows 汇流成带显式时间戳的 PlannedPacket,按时间排序后再构建。
	planned, err := plan.Plan(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		return 1
	}
	pkts, err := builder.BuildPlanned(planned)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		return 1
	}
	if err := writer.Write(*out, s.LinkType, pkts); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		return 1
	}
	printGenerationSummary(*out, planned, pkts)
	return 0
}

func printGenerationSummary(path string, planned []scenario.PlannedPacket, pkts []builder.OutPacket) {
	fmt.Printf("生成文件: %s\n", path)
	fmt.Println("Pcap组成:")
	for _, line := range summary.FormatPacketSummaries(summary.SummarizeOut(planned, pkts)) {
		fmt.Println(line)
	}
	fmt.Printf("已生成 %d 个包\n", len(pkts))
}

// cmdValidate 串接:Load + 校验。
func cmdValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("f", "", "输入场景文件 (YAML)")
	if rc, ok := parseFlags(fs, args); !ok {
		return rc
	}

	if *in == "" {
		fmt.Fprintln(os.Stderr, "validate: 需要 -f <scenario>")
		return 2
	}

	s, err := scenario.Load(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "validate:", err)
		return 1
	}
	if err := scenario.Validate(s); err != nil {
		fmt.Fprintln(os.Stderr, "validate:", err)
		return 1
	}
	for _, w := range scenario.Warnings(s) {
		fmt.Fprintf(os.Stderr, "warn: [%s] %s\n", w.Code, w.Message)
	}
	fmt.Printf("OK: %s,%d 个包,%d 条 flow\n", *in, len(s.Packets), len(s.Flows))
	return 0
}
