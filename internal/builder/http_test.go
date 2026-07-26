package builder_test

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// 本文件覆盖 HTTP 应用层序列化:回读 http_stack,断言请求行与 Host 头。

// TestParseBackHTTP 回读 http_stack,断言 Ethernet/IPv4/TCP 与 HTTP 请求行。
func TestParseBackHTTP(t *testing.T) {
	data, _ := genPcap(t, "../../examples/http/stack.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(pkts))
	}
	p := pkts[0]
	for _, lt := range []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeIPv4, layers.LayerTypeTCP} {
		if p.Layer(lt) == nil {
			t.Errorf("缺少 %v 层", lt)
		}
	}
	app := p.ApplicationLayer()
	if app == nil || !bytes.Contains(app.Payload(), []byte("GET /index.html HTTP/1.1")) {
		t.Errorf("payload 不含预期的 HTTP 请求行")
	}
	if app != nil && !bytes.Contains(app.Payload(), []byte("Host: example.com")) {
		t.Errorf("payload 不含 Host 头")
	}
}
