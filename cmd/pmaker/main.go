// Command pmaker 从声明式场景文件(YAML/JSON)生成 pcap,
// 用于对 NDR/IDS 等流量监测设备做检测能力测试。设计见仓库根目录 CLAUDE.md。
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/flow"
	"github.com/Epicccal/pMaker/internal/scenario"
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

// cmdGen 串接:Load -> Validate -> flow.Expand -> Build -> Write。
func cmdGen(args []string) int {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	in := fs.String("f", "", "输入场景文件 (YAML)")
	out := fs.String("o", "", "输出 pcap 文件")
	_ = fs.Parse(args)

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
	// flows 展开成 stack 包,拼到 packets 后走同一条构建链路。
	for _, f := range s.Flows {
		fp, err := flow.Expand(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gen:", err)
			return 1
		}
		s.Packets = append(s.Packets, fp...)
	}
	pkts, err := builder.Build(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		return 1
	}
	if err := writer.Write(*out, s.LinkType, pkts); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		return 1
	}
	printGenerationSummary(*out, s.Packets, len(pkts))
	return 0
}

func printGenerationSummary(path string, packets []scenario.Packet, count int) {
	fmt.Printf("生成文件: %s\n", path)
	fmt.Println("Pcap组成:")
	for i, summary := range scenario.SummarizePackets(packets) {
		fmt.Println(scenario.FormatPacketSummary(i+1, summary))
	}
	fmt.Printf("已生成 %d 个包\n", count)
}

// cmdValidate 串接:internal/scenario.Load + 校验。
func cmdValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	in := fs.String("f", "", "输入场景文件 (YAML/JSON)")
	_ = fs.Parse(args)

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
	fmt.Printf("OK: %s,%d 个包,%d 条 flow\n", *in, len(s.Packets), len(s.Flows))
	return 0
}
