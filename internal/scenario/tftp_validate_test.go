package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// tftp_validate_test.go 覆盖 tftp 层与 tftp_transfer 宏的硬错矩阵。
// 软告警矩阵在 tftp_consistency_test.go;wire 编码在 internal/builder;
// 宏展开规则在 internal/flow。

// tftpUDPStack 是最小合法 TFTP UDP 会话 flow.stack(dport=69)。
const tftpUDPStack = `      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.2" }
      - udp:  { sport: 50000, dport: 69 }
      - udp_session: {}
`

// tftpFlowMessages 把消息段拼进最小 flow。
func tftpFlowMessages(msgs string) string {
	return "link_type: ethernet\nflows:\n  - name: f\n    stack:\n" + tftpUDPStack +
		"    messages:\n" + msgs
}

// validateYAML 走 Load + Validate,返回错误(两者任一层的硬错都算)。
func validateYAML(t *testing.T, body string) error {
	t.Helper()
	s, err := scenario.Load(writeScenario(t, "tftp.yaml", body))
	if err != nil {
		return err
	}
	return scenario.Validate(s)
}

// TestTFTPValidateRejects 硬错矩阵:每个用例须报错且文案含 want。
func TestTFTPValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "未知字符串 opcode",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp: { opcode: fetch, filename: \"a.txt\" }\n"),
			want: `未知 opcode "fetch"`,
		},
		{
			name: "缺 opcode",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp: { filename: \"a.txt\" }\n"),
			want: "opcode 必填",
		},
		{
			// 显式 null 此前会被 Decode(&uint64) 当 0 静默透传,产成 opcode=0 的包;
			// 必须在校验期硬错。`opcode:`(空值)同为 !!null 标量。
			name: "显式 null opcode",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp: { opcode: null }\n"),
			want: "opcode 必填",
		},
		{
			name: "波浪线 null opcode",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp: { opcode: ~ }\n"),
			want: "opcode 必填",
		},
		{
			name: "空值 opcode",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp:\n              opcode:\n              filename: \"a.txt\"\n"),
			want: "opcode 必填",
		},
		{
			name: "空串 opcode",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp: { opcode: \"\", filename: \"a.txt\" }\n"),
			want: "opcode 不能为空串",
		},
		{
			name: "rrq 缺 filename",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp: { opcode: rrq, mode: octet }\n"),
			want: "opcode rrq 需要 filename",
		},
		{
			name: "选项缺 name",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp:\n              opcode: rrq\n              filename: \"a\"\n              options:\n                - { value: \"1024\" }\n"),
			want: "options[0] 需要 name",
		},
		{
			name: "选项缺 value",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp:\n              opcode: rrq\n              filename: \"a\"\n              options:\n                - { name: blksize }\n"),
			want: "options[0] 需要 value",
		},
		{
			name: "data 缺 block",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp: { opcode: data, data: \"x\" }\n"),
			want: "opcode data 需要 block",
		},
		{
			name: "ack 缺 block",
			body: tftpFlowMessages("      - from: dst\n        stack:\n" +
				"          - tftp: { opcode: ack }\n"),
			want: "opcode ack 需要 block",
		},
		{
			name: "data 与 data_hex 并存",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp: { opcode: data, block: 1, data: \"a\", data_hex: \"0x01\" }\n"),
			want: "data 和 data_hex 只能配置一个",
		},
		{
			name: "error 未知 code 名",
			body: tftpFlowMessages("      - from: dst\n        stack:\n" +
				"          - tftp: { opcode: error, code: no_such_code, message: \"boom\" }\n"),
			want: `未知 code "no_such_code"`,
		},
		{
			name: "oack 空 options",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp: { opcode: oack, options: [] }\n"),
			want: "options 至少一个",
		},
		{
			name: "tftp_transfer 在 standalone packets",
			body: "link_type: ethernet\npackets:\n  - stack:\n" +
				"      - eth:  { src: \"00:11:22:33:44:55\", dst: \"66:77:88:99:aa:bb\" }\n" +
				"      - ipv4: { src: \"10.0.0.10\", dst: \"10.0.0.2\" }\n" +
				"      - udp:  { sport: 50000, dport: 69 }\n" +
				"      - tftp_transfer: { data: \"hi\" }\n",
			want: "tftp_transfer 只能作为 UDP flow 的 messages[].stack 的唯一一层",
		},
		{
			name: "tftp_transfer 在 flow.stack",
			body: "link_type: ethernet\nflows:\n  - name: f\n    stack:\n" +
				strings.Replace(tftpUDPStack, "      - udp_session: {}", "      - tftp_transfer: { data: \"hi\" }\n      - udp_session: {}", 1) +
				"    messages:\n      - from: src\n        stack:\n          - payload: { payload: \"hi\" }\n",
			want: "flow.stack 不支持该层",
		},
		{
			name: "tftp_transfer 与其他层共存",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp: { opcode: oack, options: [{ name: blksize, value: \"512\" }] }\n" +
				"          - tftp_transfer: { data: \"hi\" }\n"),
			want: "tftp_transfer 须是该消息唯一的一层",
		},
		{
			name: "tftp_transfer 在 TCP flow",
			body: "link_type: ethernet\nflows:\n  - name: f\n    stack:\n" +
				"      - eth:  { src: \"00:11:22:33:44:55\", dst: \"66:77:88:99:aa:bb\" }\n" +
				"      - ipv4: { src: \"10.0.0.10\", dst: \"10.0.0.2\" }\n" +
				"      - tcp:  { sport: 40001, dport: 69 }\n" +
				"      - tcp_session: {}\n" +
				"    messages:\n      - from: src\n        stack:\n" +
				"          - tftp_transfer: { data: \"hi\" }\n",
			want: "tftp_transfer 只能用于 UDP flow",
		},
		{
			name: "tftp_transfer block_size 0",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp_transfer: { data: \"hi\", block_size: 0 }\n"),
			want: "block_size 须 ≥ 1",
		},
		{
			name: "tftp_transfer data 与 data_hex 并存",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp_transfer: { data: \"hi\", data_hex: \"0x01\" }\n"),
			want: "data 和 data_hex 只能配置一个",
		},
		{
			// 块号溢出须在 Validate 阶段就拦截,否则 validate / generate_yaml 报绿,
			// 到 gen / generate_pcap 展开宏时才硬错(flow.expandTransferMacro)。
			name: "tftp_transfer 块数超 65535",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp_transfer: { data: \"" + strings.Repeat("a", 65535) + "\", block_size: 1 }\n"),
			want: "超过块号上限 65535",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateYAML(t, tc.body)
			if err == nil {
				t.Fatalf("期望报错含 %q,实际通过", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望报错含 %q,得到: %v", tc.want, err)
			}
		})
	}
}

// TestTFTPValidateAccepts 合法矩阵:数字 opcode / block: 0 / 空数据末块 /
// 数字 code / 宏合法位置等,须零硬错零告警。
func TestTFTPValidateAccepts(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "数字 opcode 7 透传",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp: { opcode: 7 }\n"),
		},
		{
			name: "data block 0 合法畸形",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp: { opcode: data, block: 0, data_hex: 0xdeadbeef }\n"),
		},
		{
			name: "data 空数据 0 字节末块",
			body: tftpFlowMessages("      - from: src\n        stack:\n" +
				"          - tftp: { opcode: data, block: 1 }\n"),
		},
		{
			name: "error 数字 code 8",
			body: tftpFlowMessages("      - from: dst\n        stack:\n" +
				"          - tftp: { opcode: error, code: 8, message: \"bad option\" }\n"),
		},
		{
			// error code 的 null 走缺省 0,与未写同语义,不算硬错。
			name: "error null code 缺省 0",
			body: tftpFlowMessages("      - from: dst\n        stack:\n" +
				"          - tftp: { opcode: error, code: null, message: \"boom\" }\n"),
		},
		{
			name: "ack block 0 确认 OACK",
			body: tftpFlowMessages("      - from: dst\n        stack:\n" +
				"          - tftp: { opcode: ack, block: 0 }\n"),
		},
		{
			name: "宏在合法位置",
			body: tftpFlowMessages("      - from: src\n        message_id: xfer\n        stack:\n" +
				"          - tftp_transfer: { data: \"hi\", block_size: 8, interval: \"+2ms\" }\n"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateYAML(t, tc.body); err != nil {
				t.Fatalf("应通过校验: %v", err)
			}
		})
	}
}

// TestTFTPTransferInQuoteStack:宏出现在 icmp.quote.stack 时由 validateLayerIn
// 的无条件拒绝 case 拦截(所有非合法位置共用同一条报错)。
func TestTFTPTransferInQuoteStack(t *testing.T) {
	body := `link_type: ethernet
packets:
  - name: bad
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - icmp: { type: 3, code: 1 }
      - ipv4: { src: "10.0.0.3", dst: "10.0.0.4" }
      - udp:  { sport: 50000, dport: 69 }
      - tftp_transfer: { data: "hi" }
`
	if err := validateYAML(t, body); err == nil ||
		!strings.Contains(err.Error(), "tftp_transfer 只能作为 UDP flow 的 messages[].stack 的唯一一层") {
		t.Fatalf("quote.stack 里的宏应被拒,得到: %v", err)
	}
}
