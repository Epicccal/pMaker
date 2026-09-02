package scenario

import (
	"fmt"
	"strings"
)

// 本文件实现 IMAP4rev2(RFC 9051)命令 / 响应字段的「合法基线」校验。
//
// IMAP 与 POP3/SMTP 等一行式文本协议的根本差异:IMAP 是「行 + 长度前缀混合定界」
// (RFC 9051 §2.2),literal 嵌在命令/响应中间,前后都有文本。故 imap_request 三形式
// (命令行 / 裸行 / literal 八位组)、imap_response 状态组与数据组互斥(决策 7)。
//
// 校验只判合法性,绝不改变序列化行为(序列化在 builder/imap.go)。无法用结构化字段
// 表达的畸形(私有命令、非末位 literal、缺空格的状态行、非标间距)走 payload / payload_hex。
//
// 文法依据见 RFC 9051 §9 Formal Syntax(已核对原文,非记忆复述)。

// imapState 是 IMAP 命令按连接状态的分组(RFC 9051 §9:command-any/nonauth/auth/select)。
// 本轮只登记不强制(状态机校验需跨消息上下文,留待后续),先把数据放进单源表。
type imapState int

const (
	imapAny     imapState = iota // command-any:任意状态合法(CAPABILITY/LOGOUT/NOOP)
	imapNonAuth                  // command-nonauth:未认证(LOGIN/AUTHENTICATE/STARTTLS)
	imapAuth                     // command-auth:已认证(APPEND/SELECT/LIST/…)
	imapSelect                   // command-select:已选邮箱(CLOSE/FETCH/STORE/…)
)

// imapArgsPolicy 复用 POP3/SMTP 的 args 有/无策略语义(required/forbidden/optional)。
type imapArgsPolicy int

const (
	imapArgsRequired  imapArgsPolicy = iota // 必带 args
	imapArgsForbidden                       // 禁带 args
	imapArgsOptional                        // 可选 args
)

// imapCmd 描述一条 IMAP 命令的元信息:连接状态分组 + args 要求策略。
type imapCmd struct {
	state imapState
	args  imapArgsPolicy
}

// imapCommands 是 IMAP 已知命令表(单源):键 = 大写命令名,值 = 状态组 + args 策略。
// 成员关系即「已知命令」,args 有/无按策略校验。单表而非两张表:加命令只在此一处,
// 不存在「加了一处忘了另一处、新命令被 map 缺键零值静默当作某策略」的路径。
//
// 命令表取 rev1(RFC 3501)∪ rev2(RFC 9051)并集(决策 6),额外收入 LSUB/CHECK 等
// rev1-only 命令,天然兼容两版;不设版本开关,避免「构造 rev1 畸形要先切 schema」的摩擦。
// IDLE(RFC 2177)、UNSELECT(3691)、MOVE(6851)、NAMESPACE(2342)、ENABLE(5161)已并入 9051 核心。
var imapCommands = map[string]imapCmd{
	// command-any(RFC 9051 §9)
	"CAPABILITY": {imapAny, imapArgsForbidden},
	"LOGOUT":     {imapAny, imapArgsForbidden},
	"NOOP":       {imapAny, imapArgsForbidden},
	// command-nonauth
	"LOGIN":        {imapNonAuth, imapArgsRequired},
	"AUTHENTICATE": {imapNonAuth, imapArgsRequired},
	"STARTTLS":     {imapNonAuth, imapArgsForbidden},
	// command-auth
	"APPEND":      {imapAuth, imapArgsRequired},
	"CREATE":      {imapAuth, imapArgsRequired},
	"DELETE":      {imapAuth, imapArgsRequired},
	"ENABLE":      {imapAuth, imapArgsRequired},
	"EXAMINE":     {imapAuth, imapArgsRequired},
	"LIST":        {imapAuth, imapArgsRequired},
	"NAMESPACE":   {imapAuth, imapArgsForbidden},
	"RENAME":      {imapAuth, imapArgsRequired},
	"SELECT":      {imapAuth, imapArgsRequired},
	"STATUS":      {imapAuth, imapArgsRequired},
	"SUBSCRIBE":   {imapAuth, imapArgsRequired},
	"UNSUBSCRIBE": {imapAuth, imapArgsRequired},
	"IDLE":        {imapAuth, imapArgsForbidden},
	"LSUB":        {imapAuth, imapArgsRequired}, // rev1(RFC 3501),rev2 已废弃,保留构造能力
	// command-select
	"CLOSE":    {imapSelect, imapArgsForbidden},
	"UNSELECT": {imapSelect, imapArgsForbidden},
	"EXPUNGE":  {imapSelect, imapArgsOptional}, // rev2 无参;UID EXPUNGE 走 UID
	"COPY":     {imapSelect, imapArgsRequired},
	"MOVE":     {imapSelect, imapArgsRequired},
	"FETCH":    {imapSelect, imapArgsRequired},
	"STORE":    {imapSelect, imapArgsRequired},
	"SEARCH":   {imapSelect, imapArgsRequired},
	"UID":      {imapSelect, imapArgsRequired},
	"CHECK":    {imapSelect, imapArgsForbidden}, // rev1,rev2 已废弃
}

// validateIMAPTag 校验 IMAP tag(RFC 9051 §9:tag = 1*<any ASTRING-CHAR except "+">)。
// + 被显式排除(与 continuation 的 + 前缀歧义);] 合法(resp-specials 被加回来)。
// 故不能简单写成「字母数字」——那会拒掉 RFC 允许的 tag。
//
// 规则:非空、不含 +、不含 atom-specials 的子集(( ) { SP CTL % * " \)。
// CTL(0x00-0x1F + 0x7F)统一拦截;] 放行(resp-specials)。
// 非标 tag(含 + 等)走 payload / payload_hex 显式落字节。
func validateIMAPTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("需要 tag")
	}
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		switch {
		case c == '+':
			return fmt.Errorf("tag %q 含 '+',IMAP tag 不得包含 '+'(RFC 9051 §9:tag 排除 '+',与 continuation '+ ' 前缀歧义);非标 tag 请用 payload / payload_hex", tag)
		case c == '(' || c == ')' || c == '{' || c == ' ' || c == '%' || c == '*' || c == '"' || c == '\\':
			return fmt.Errorf("tag %q 含非法字符 %q(RFC 9051 §9 atom-specials;']' 合法故放行);非标 tag 请用 payload / payload_hex", tag, string(c))
		case c < 0x20 || c == 0x7f:
			return fmt.Errorf("tag %q 含控制字符(RFC 9051 §9 CTL);非标 tag 请用 payload / payload_hex", tag)
		}
	}
	return nil
}

// validateIMAPCommand 校验 imap_request.command:非空且属于已知命令表(大小写不敏感)。
// 未列入表的命令报错,并引导改用 payload / payload_hex 构造非标 / 私有命令。
// 返回大写化的 command(供 args 策略分派用)。command 原样输出(不强制大写)。
func validateIMAPCommand(c string) (string, error) {
	if c == "" {
		return "", fmt.Errorf("需要 command")
	}
	uc := strings.ToUpper(c)
	if _, ok := imapCommands[uc]; !ok {
		return "", fmt.Errorf("未知 IMAP 命令 %q(支持 RFC 9051 核心 CAPABILITY/LOGIN/SELECT/FETCH/APPEND/STORE/IDLE 等;非标或私有命令请用 payload / payload_hex)", c)
	}
	return uc, nil
}

// imapStatusWords 是 IMAP 响应状态码白名单(RFC 9051 §9 resp-cond-state / resp-cond-bye / resp-cond-auth)。
// tagged 响应仅 OK/NO/BAD(resp-cond-state);PREAUTH/BYE 只能 untagged。
//
// 这几个关键字只会出现在 Status 参数中，不应当出现在 Data 开头，避免用户误写
var imapStatusWords = map[string]bool{
	"OK": true, "NO": true, "BAD": true, "PREAUTH": true, "BYE": true,
}

// imapLiteralEmitValid 是 literal.emit 合法值集合。
var imapLiteralEmitValid = map[string]bool{"": true, "full": true, "prefix": true, "data": true}

// validateIMAPLiteral 校验 IMAPLiteral 字段组合的合法性。
//   - 八位组内容 eml / data / data_hex 三选一(全空报错:literal 无内容无意义);
//   - data_hex 须为合法 0x 前缀十六进制;
//   - octets 非 nil 时须非负(负值无意义);
//   - emit ∈ {full(缺省)/prefix/data};
//   - sync 缺省 true;binary: true 且 sync: false → 硬错(决策 8:literal8 无 {n+} 非同步形式,
//     ~{n+} 不是任何已定义 token,会绕过成帧校验产出孤儿字节流);
//   - eml 非空时委托 validateEMLDataFields 校验(复用,不重复实现)。
//
// fromServer 标记本 literal 是否出现在 imap_response(server→client)下:是则 sync: false 报错
// (RFC 9051 §4.3:非同步 literal 仅 client→server,server MUST NOT 发)。
func validateIMAPLiteral(f *IMAPLiteral, fromServer bool) error {
	hasEML := f.EML != nil
	hasData := f.Data != ""
	hasHex := f.DataHex != ""
	kinds := 0
	for _, p := range []bool{hasEML, hasData, hasHex} {
		if p {
			kinds++
		}
	}
	if kinds == 0 {
		return fmt.Errorf("literal 需要 eml / data / data_hex(空 literal 无意义)")
	}
	if kinds > 1 {
		return fmt.Errorf("eml / data / data_hex 只能配置一个")
	}
	if hasHex {
		if _, err := ParsePayloadHex(f.DataHex); err != nil {
			return fmt.Errorf("data_hex: %w", err)
		}
	}
	if f.Octets != nil && *f.Octets < 0 {
		return fmt.Errorf("octets 不得为负(得到 %d)", *f.Octets)
	}
	if !imapLiteralEmitValid[f.Emit] {
		return fmt.Errorf("emit %q 非法,只能是 full / prefix / data", f.Emit)
	}
	// sync 缺省 true:nil 或 *true = 同步 {n};*false = 非同步 {n+}。
	sync := f.Sync == nil || *f.Sync
	if !sync {
		if fromServer {
			return fmt.Errorf("非同步 literal({n+})不得由服务器发往客户端(RFC 9051 §4.3 MUST NOT);服务器侧 literal 须 sync: true")
		}
		if f.Binary {
			return fmt.Errorf("literal8 无非同步形式(RFC 9051 §4.3.1 / §9:仅 {n+} 支持非同步,BINARY literal 须 sync: true;~{n+} 不是已定义 token);如需构造 ~{n+} 字节走 payload_hex")
		}
	}
	if hasEML {
		if err := validateEMLDataFields(f.EML); err != nil {
			return fmt.Errorf("eml: %w", err)
		}
	}
	return nil
}

// validateIMAPRequestFields 校验 imap_request 字段组合的合法性(三形式互斥判别)。
//
// 三形式(决策 1):
//   - 形式 A 命令行:tag + command [+ args] [+ literal];
//   - 形式 B 裸行:  line(DONE / SASL base64 续行 / 取消 literal 的 *);
//   - 形式 C 八位组:literal.emit = data(同步 literal 第二个 TCP 消息)。
//
// 互斥规则:
//   - line 与 tag/command/args 同设报错(形式 B 与形式 A 互斥;形式 B 无参数位);
//   - emit: data 时 tag/command/args 须为空(形式 C 独立八位组消息,无命令行);
//   - 形式 A:tag 经 validateIMAPTag、command 经 validateIMAPCommand,args 按策略校验有/无;
//   - 所有文本字段(args/line)禁含裸 \r \n(会注入额外命令行);畸形走 payload/payload_hex。
//
// literal 可附在形式 A 命令行末尾(emit: full/prefix),或作为形式 C 独立消息(emit: data)。
func validateIMAPRequestFields(f *IMAPRequestFields) error {
	hasLine := f.Line != ""
	hasTag := f.Tag != ""
	hasCmd := f.Command != ""
	hasArgs := f.Args != ""
	hasLiteral := f.Literal != nil

	// literal.emit = data 是形式 C:独立八位组消息,不得带 tag/command/args/line。
	emitIsData := hasLiteral && f.Literal.Emit == "data"

	// line 与 tag/command/args 互斥(形式 B 与形式 A)。
	// 放行只会被序列化层静默丢弃;尾随垃圾等畸形直接写进 line。
	if hasLine && (hasTag || hasCmd || hasArgs) {
		return fmt.Errorf("line 与 tag/command/args 互斥(line 是裸行形式 B:DONE / SASL base64 续行 / 取消 literal 的 *,整行内容都写在 line 里;命令行形式 A 用 tag+command[+args])")
	}
	if emitIsData && (hasTag || hasCmd || hasArgs || hasLine) {
		return fmt.Errorf("literal.emit: data 是独立八位组消息(形式 C),不得带 tag/command/args/line")
	}

	// 文本字段禁止存在 CRLF
	if hasCRLF(f.Args) {
		return fmt.Errorf("args 不能包含 \\r 或 \\n(会注入额外命令行;畸形 IMAP 字节流请用 payload / payload_hex)")
	}
	if hasCRLF(f.Line) {
		return fmt.Errorf("line 不能包含 \\r 或 \\n(会注入额外命令行;畸形 IMAP 字节流请用 payload / payload_hex)")
	}

	if emitIsData {
		// 形式 C:仅 literal(emit=data)。
		return validateIMAPLiteral(f.Literal, false)
	}

	if hasLine {
		// 形式 B:裸行(line)。literal 不应与裸行同现(裸行无 literal 前缀语义)。
		if hasLiteral {
			return fmt.Errorf("line(裸行)与 literal 互斥(裸行不携带长度前缀)")
		}
		return nil
	}

	// 形式 A:命令行。tag + command 必填。
	if err := validateIMAPTag(f.Tag); err != nil {
		return err
	}
	uc, err := validateIMAPCommand(f.Command)
	if err != nil {
		return err
	}
	switch imapCommands[uc].args {
	case imapArgsRequired:
		if !hasArgs && !hasLiteral {
			return fmt.Errorf("%s 需要 args(如 LOGIN 需要 userid SP password)", f.Command)
		}
		// 有 literal 时 args 可空(literal 本身是命令的一个参数,如 APPEND 的邮件正文)。
	case imapArgsForbidden:
		if hasArgs {
			return fmt.Errorf("%s 不接受参数(畸形请用 payload / payload_hex)", f.Command)
		}
	case imapArgsOptional:
		// 有/无均合规(EXPUNGE)。
	}
	if hasLiteral {
		return validateIMAPLiteral(f.Literal, false)
	}
	return nil
}

// validateIMAPResponseFields 校验 imap_response 字段组合的合法性(决策 7:状态组/数据组互斥)。
//
// tag 三态定型:具体 tag = tagged;"*" = untagged;"+" = continuation。首 token 互斥。
//   - tag "+" :仅 text 允许(可空,continue-req = "+" SP (resp-text / base64) CRLF);
//   - 具体 tag:状态组 status(仅 OK/NO/BAD) + code + text;禁 data/literal/tail、禁 PREAUTH/BYE;
//   - "*"     :状态组 status(全部五值) + code + text  XOR  数据组 data + literal + tail;
//
// 状态组/数据组互斥五条一组(决策 7):
//  1. status 与 data 互斥(两个都写报错);
//  2. data 的首 token(后跟 SP 或行尾,大小写不敏感)不得为 OK/NO/BAD/PREAUTH/BYE
//     (这条才真正封死「状态响应误写进 data」的歧义);
//  3. data 非空时 tag 必须是 *(tagged 响应文法上恒为状态形式);
//  4. code/text 不得与 data 同现;literal/tail 非空时 data 须非空(须依附数据组);
//  5. 状态组或数据组至少一组非空(全空报错);text/code 不得脱离 status 单独存在
//     (无 status 时 text/code 在序列化层无落点,会被静默丢弃;RFC 9051 §9 status 字强制)。
//
// 所有文本字段(status/code/text/data/tail)禁含裸 \r \n;code 额外禁含 ](方括号码定界);
// 具体 tag(非 "*" / "+")经 validateIMAPTag 校验字符集(与 imap_request 同一套)。
func validateIMAPResponseFields(f *IMAPResponseFields) error {
	if f.Tag == "" {
		return fmt.Errorf("需要 tag(tag / \"*\" / \"+\")")
	}
	// 具体 tag(非 "*" / "+")走与 imap_request 同一套字符集校验:
	// 未校验的 tag 会被 serializeIMAPResp 的 default 分支原样落字节,
	// 含 CRLF 的 tag 可注入一整条额外响应行(status/code/text/data/tail 的 CRLF 防护同一目的),
	// 含 * 等 atom-specials 的 tag(如 "*extra")还会绕过下文 f.Tag == "*" 的分流,
	// 产出既非 untagged 也非合法 tagged 的字节。畸形 tag 走 payload / payload_hex。
	if f.Tag != "*" && f.Tag != "+" {
		if err := validateIMAPTag(f.Tag); err != nil {
			return err
		}
	}
	hasStatus := f.Status != ""
	hasCode := f.Code != ""
	hasText := f.Text != ""
	hasData := f.Data != ""
	hasLiteral := f.Literal != nil
	hasTail := f.Tail != ""

	// 文本字段 CRLF 注入防护。
	for _, field := range []struct{ name, val string }{
		{"status", f.Status}, {"code", f.Code}, {"text", f.Text},
		{"data", f.Data}, {"tail", f.Tail},
	} {
		if hasCRLF(field.val) {
			return fmt.Errorf("%s 不能包含 \\r 或 \\n(会注入额外响应行;畸形 IMAP 字节流请用 payload / payload_hex)", field.name)
		}
	}
	// code 额外禁含 ](resp-text-code 方括号内内容,] 是定界符)。
	if hasCode && strings.Contains(f.Code, "]") {
		return fmt.Errorf("code 不能包含 ']'(resp-text-code 方括号内内容,']' 是定界符;畸形请用 payload / payload_hex)")
	}

	// tag "+" :仅 text 允许(continue-req = "+" SP (resp-text / base64) CRLF)。
	// text 可空:resp-text = ["[" code "]"] *TEXT-UTF8-CHAR,*TEXT-UTF8-CHAR 允许零字符,
	// 故 "+ \r\n"(SASL 空挑战)是合法形态(RFC 9051 §9)。裸 "+"(无 SP)走 payload / payload_hex。
	if f.Tag == "+" {
		if hasStatus || hasCode || hasData || hasLiteral || hasTail {
			return fmt.Errorf("tag \"+\" 是 continuation 请求('+ ' SP (resp-text / base64) CRLF),仅允许 text 字段")
		}
		return nil
	}

	// 1. status 与 data 互斥。
	if hasStatus && hasData {
		return fmt.Errorf("status 与 data 互斥(状态响应用 status+code+text,数据响应用 data+literal+tail;非标间距等成帧畸形走 payload / payload_hex)")
	}

	// 2. data 的首 token 不得为 OK/NO/BAD/PREAUTH/BYE(封死状态响应误写进 data)。
	if hasData {
		if bad := imapDataFirstTokenIsStatus(f.Data); bad {
			return fmt.Errorf("data 的首 token 不得是 OK/NO/BAD/PREAUTH/BYE(那是状态形式,合规写法用 status + code + text;非标间距等成帧畸形走 payload / payload_hex)")
		}
	}

	// 3. data 非空时 tag 必须是 *(tagged 响应文法上恒为状态形式)。
	if hasData && f.Tag != "*" {
		return fmt.Errorf("data 仅 untagged 响应(tag=\"*\")可用(tagged 响应文法上恒为状态形式,用 status+code+text)")
	}

	// 4. code/text 不得与 data 同现;literal/tail 须依附 data。
	if hasData && (hasStatus || hasCode || hasText) {
		return fmt.Errorf("data(数据组)与 status/code/text(状态组)不可同现")
	}
	if (hasLiteral || hasTail) && !hasData {
		return fmt.Errorf("literal / tail 须依附 data(数据组:literal 嵌在 data 之后,tail 紧随其后)")
	}

	// 状态组校验:status 白名单 + tagged 限 OK/NO/BAD。
	if hasStatus {
		us := strings.ToUpper(f.Status)
		if !imapStatusWords[us] {
			return fmt.Errorf("status %q 非法,只能是 OK / NO / BAD / PREAUTH / BYE(大小写不敏感;非标状态码请用 payload / payload_hex)", f.Status)
		}
		if f.Tag != "*" { // tagged 响应:仅 OK/NO/BAD
			if us != "OK" && us != "NO" && us != "BAD" {
				return fmt.Errorf("tagged 响应(具体 tag)的 status 只能是 OK / NO / BAD(RFC 9051 §9 response-tagged = tag SP resp-cond-state);%s 只能 untagged(tag=\"*\")", f.Status)
			}
		}
	}

	// 5. 至少一组非空(全空报错)。
	// text/code 不再单独让响应合法:text/code 只在状态组(status 非空)才有落点,
	// 没有 status 时被序列化层静默丢弃(RFC 9051 §9 response-tagged = tag SP resp-cond-state,
	// status 字强制;untagged 同理首 token 固定)。故非 continuation 响应须有 status 或 data。
	if !hasStatus && !hasData {
		return fmt.Errorf("需要 status+code+text(状态组)或 data+literal+tail(数据组);text/code 不得脱离 status 单独存在(RFC 9051 §9:status 字强制),全空或孤儿 text/code 响应走 payload / payload_hex")
	}

	if hasLiteral {
		// imap_response 下 literal 是 server→client:非同步 {n+} 禁止(决策 8 + RFC §4.3)。
		if err := validateIMAPLiteral(f.Literal, true); err != nil {
			return err
		}
	}
	return nil
}

// imapDataFirstTokenIsStatus 取 data 的首 token,判定是否为状态形式首 token
// (OK/NO/BAD/PREAUTH/BYE,后跟 SP 或行尾,大小写不敏感)。用于封死「状态响应误写进 data」
// 的歧义(决策 7):数据形式首 token 恒为数字或 FLAGS/LIST/STATUS 等 atom,与这五个词不碰。
func imapDataFirstTokenIsStatus(data string) bool {
	t := strings.TrimLeft(data, " \t")
	end := len(t)
	for i, r := range t {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			end = i
			break
		}
	}
	tok := strings.ToUpper(t[:end])
	return imapStatusWords[tok]
}
