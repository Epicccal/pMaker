package builder_test

import (
	"bytes"
	"testing"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 FTP 应用层序列化:回读 ftp/control,断言命令与响应符合 RFC 959。

// TestSerializeFTPRespEmptyLines 断言 FTP 多行响应中 lines 的空元素被如实输出、不静默丢弃
// (RFC 959 §4.2 续行空文本行协议合法)。走 builder.PayloadBytes 与 serializeStack 同一序列化路径。
// FTP 续行格式(RFC 959 §4.2):
//   - 首行 "code-text\r\n"(code 后紧跟连字符);
//   - 中间行裸文本(无 code 前缀),空元素 → 裸空行 "\r\n";
//   - 末行 "code[ SP text]\r\n",末行空文本 → "code \r\n"(code + 空格)。
func TestSerializeFTPRespEmptyLines(t *testing.T) {
	cases := []struct {
		name string
		f    scenario.FTPResponseFields
		want string
	}{
		{
			name: "三行含中间空元素(中间行裸文本)",
			f: scenario.FTPResponseFields{
				Code:  220,
				Lines: []string{"Welcome to pMaker FTP service.", "", "All transfers are logged."},
			},
			// 首行 220-、中间空元素→裸空行、末行 220 SP
			want: "220-Welcome to pMaker FTP service.\r\n\r\n220 All transfers are logged.\r\n",
		},
		{
			name: "两行末行空元素(FTP 末行恒带空格)",
			f:    scenario.FTPResponseFields{Code: 220, Lines: []string{"Welcome", ""}},
			want: "220-Welcome\r\n220 \r\n",
		},
		{
			name: "单行空message",
			f:    scenario.FTPResponseFields{Code: 220},
			want: "220\r\n",
		},
		{
			name: "单行message",
			f:    scenario.FTPResponseFields{Code: 331, Message: "Please specify the password."},
			want: "331 Please specify the password.\r\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := builder.PayloadBytes(scenario.Layer{
				Type:   "ftp_response",
				Fields: &c.f,
			})
			if err != nil {
				t.Fatalf("PayloadBytes: %v", err)
			}
			if !bytes.Equal(got, []byte(c.want)) {
				t.Errorf("PayloadBytes = %q, want %q", got, c.want)
			}
		})
	}
}

// TestParseBackFTP 回读 ftp/control.yaml,断言两个包的 TCP payload 含 FTP 命令与响应,
// 证明 ftp_request/ftp_response 序列化符合 RFC 959(command 原样、code message\r\n)。
func TestParseBackFTP(t *testing.T) {
	data, _ := genPcap(t, "../../examples/ftp/control.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 2 {
		t.Fatalf("期望 2 个包,得到 %d", len(pkts))
	}
	p0 := pkts[0].ApplicationLayer()
	if p0 == nil || string(p0.Payload()) != "USER anonymous\r\n" {
		t.Errorf("包0 FTP 命令=%q,期望 USER anonymous\\r\\n", p0)
	}
	p1 := pkts[1].ApplicationLayer()
	if p1 == nil || string(p1.Payload()) != "331 Please specify the password.\r\n" {
		t.Errorf("包1 FTP 响应=%q,期望 331 ...\\r\\n", p1)
	}
}
