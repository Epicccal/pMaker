package builder_test

import (
	"testing"
)

// 本文件覆盖 FTP 应用层序列化:回读 ftp/control,断言命令与响应符合 RFC 959。

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
