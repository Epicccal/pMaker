package scenario

import (
	"fmt"
	"strings"

	"github.com/Epicccal/pMaker/internal/util/crlf"
)

// 本文件实现 IMAP literal 计数覆盖值的一致性告警(非硬错),对齐 FTP 端口告警、
// multipart boundary 告警同一套 Warnings 机制。
//
// octets 两态覆盖(nil = 自动算实际字节数;非 nil = 原样落值,关闭自动计算):
// 声明 octets: 9999 而实际 342 字节是构造「计数撒谎」解析器攻击用例的合法手段,
// 必须原样落值、不得被自动修正抹平(领域约束 1:畸形包必须能绕过自动修正)。
// 但计数不一致也可能是用户笔误,故在校验阶段产出软告警供用户复核 ——
// 故意撒谎的畸形用例通过 Validate,笔误则被提醒。

// CheckIMAPLiteralConsistency 扫描所有 packet / flow message 的 imap_request / imap_response
// 层,对 literal.Octets != nil 且其值 ≠ 实际内容字节数的情况产出告警(软错)。
func CheckIMAPLiteralConsistency(s *Scenario) []string {
	if s == nil {
		return nil
	}
	var ws []string
	for i := range s.Packets {
		for j, l := range s.Packets[i].Stack {
			ws = append(ws, checkIMAPLiteralLayer("packets", fmt.Sprintf("%d.stack[%d]", i, j), l)...)
		}
	}
	for i, f := range s.Flows {
		for j, m := range f.Messages {
			for k, l := range m.Stack {
				ws = append(ws, checkIMAPLiteralLayer("flows", fmt.Sprintf("%s.messages[%d].stack[%d]", flowLabel(f.Name, i), j, k), l)...)
			}
		}
	}
	return ws
}

// checkIMAPLiteralLayer 检查单个层的 literal 计数一致性。
// loc 是告警定位前缀(如 "packets" / "flows"),path 是层路径(如 "0.stack[1]")。
func checkIMAPLiteralLayer(loc, path string, l Layer) []string {
	var lit *IMAPLiteral
	switch f := l.Fields.(type) {
	case *IMAPRequestFields:
		lit = f.Literal
	case *IMAPResponseFields:
		lit = f.Literal
	default:
		return nil
	}
	if lit == nil || lit.Octets == nil {
		return nil
	}
	declared := *lit.Octets
	actual, ok := imapLiteralActualBytes(lit)
	if !ok {
		// 无法在 scenario 包内精确计算字节(如 multipart literal),跳过告警,
		// 避免误报;精确计数仍在 builder 序列化时落地。
		return nil
	}
	if declared == actual {
		return nil
	}
	return []string{fmt.Sprintf("%s.%s: imap literal 计数不一致(声明 octets %d / 实际 %d 字节;若为故意撒谎的畸形用例可忽略此告警)", loc, path, declared, actual)}
}

// imapLiteralActualBytes 计算 literal 八位组的实际内容字节数(与 builder.imapLiteralBytes
// 的自动计数口径一致):eml → SerializeEMLData 纯内容;data → 字面字节;data_hex → 解码字节。
// 不走 builder 包(避免 scenario→builder 循环依赖),按同一口径本地计算。
// 返回 (字节数, ok);ok=false 表示无法在 scenario 包内精确计算(如 multipart literal)。
func imapLiteralActualBytes(f *IMAPLiteral) (int, bool) {
	if f.EML != nil {
		b, ok := imapLiteralEMLBytes(f.EML)
		if !ok {
			return 0, false
		}
		return len(b), true
	}
	if f.DataHex != "" {
		b, err := ParsePayloadHex(f.DataHex)
		if err != nil {
			return 0, false
		}
		return len(b), true
	}
	return len(f.Data), true
}

// imapLiteralEMLBytes 复用 eml_data 的内容字节计算口径。为避免 scenario→builder 循环依赖,
// 在 scenario 包内本地实现一份与 SerializeEMLData 同语义的纯内容计算(仅用于告警比对,
// 精确字节产出仍在 builder)。结构化模式:headers + 空行 + body(裸 \n → \r\n 归一化);
// 原始模式:raw 或 raw_hex 解码。返回 (字节, ok);multipart 返回 ok=false(拼装逻辑在
// builder,scenario 包内不重复实现,避免误报)。
//
// 行结束符归一化复用 internal/util/crlf.NormalizeCRLF(与 builder.SerializeEMLData 共用同一份
// 原语,消除两处重复实现漂移的风险);字节拼装口径(headers + 空行 + body)仍本地维护,
// 与 builder 保持等价 —— 见 internal/scenario/imap_consistency_test.go 的跨包等价测试
// (TestIMAPLiteralEMLBytes_EquivToBuilder)断言两者逐字节一致。
func imapLiteralEMLBytes(f *EMLDataFields) ([]byte, bool) {
	if f.Raw != "" || f.RawHex != "" {
		if f.RawHex != "" {
			b, err := ParsePayloadHex(f.RawHex)
			if err != nil {
				return nil, false
			}
			return b, true
		}
		return []byte(f.Raw), true
	}
	if f.Multipart != nil {
		// multipart 字节由 builder.serializeMultipart 拼装,scenario 包内不重复实现
		// (构造期极少对 multipart literal 撒谎);返回 ok=false 跳过告警,避免误报。
		return nil, false
	}
	var b strings.Builder
	f.Headers.Range(func(k, v string) {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteString("\r\n")
	})
	b.WriteString("\r\n")
	b.WriteString(crlf.NormalizeCRLF(f.Body))
	return []byte(b.String()), true
}

// imapLiteralActualBytes 的 eml 分支与 builder.SerializeEMLData 的结构化/原始模式字节口径
// 由跨包等价测试 internal/scenario/imap_consistency_test.go
// (TestIMAPLiteralEMLBytes_EquivToBuilder)锁定:同一组 EMLDataFields 喂入,断言
// imapLiteralEMLBytes 与 builder.PayloadBytes(eml_data 经成帧前的纯内容)逐字节相等。
// 改动本函数或 builder/eml_data.go 的内容口径时,该测试会捕获漂移。
