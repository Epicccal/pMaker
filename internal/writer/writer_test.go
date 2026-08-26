package writer

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/Epicccal/pMaker/internal/builder"
)

// TestLinkType 覆盖 linkType 的全部分支:五个合法名 + 未知名报错文案。
func TestLinkType(t *testing.T) {
	cases := []struct {
		name string
		want layers.LinkType
		ok   bool
	}{
		{"", layers.LinkTypeEthernet, true}, // 缺省 = ethernet
		{"ethernet", layers.LinkTypeEthernet, true},
		{"raw", layers.LinkTypeRaw, true},
		{"ipv4", layers.LinkTypeIPv4, true},
		{"ipv6", layers.LinkTypeIPv6, true},
		{"bogus", 0, false},
	}
	for _, c := range cases {
		got, err := linkType(c.name)
		if c.ok {
			if err != nil {
				t.Errorf("linkType(%q) 不应报错,得到 %v", c.name, err)
				continue
			}
			if got != c.want {
				t.Errorf("linkType(%q) = %v, 期望 %v", c.name, got, c.want)
			}
		} else {
			if err == nil {
				t.Errorf("linkType(%q) 应报错", c.name)
				continue
			}
			// 错误文案应点名未知名与支持列表,供用户定位。
			if !strings.Contains(err.Error(), c.name) {
				t.Errorf("错误应含未知名 %q,得到 %v", c.name, err)
			}
			if !strings.Contains(err.Error(), "ethernet") {
				t.Errorf("错误应列出支持项 ethernet,得到 %v", err)
			}
		}
	}
}

// samplePackets 构造两包(带确定性时间戳),供 WriteTo 测试复用。
func samplePackets() []builder.OutPacket {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	return []builder.OutPacket{
		{Data: []byte{0x01, 0x02}, Time: base},
		{Data: []byte{0x03, 0x04, 0x05}, Time: base.Add(time.Millisecond)},
	}
}

// TestWriteToFileHeader 验证写出的 pcap 文件头:魔数、版本、snaplen、linktype。
func TestWriteToFileHeader(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTo(&buf, "ethernet", samplePackets()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	r, err := pcapgo.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("pcapgo reader: %v", err)
	}
	// 文件头字段:snaplen 应为本包常量、linktype 为 ethernet。
	if got := r.Snaplen(); got != snapLen {
		t.Errorf("snaplen=%d, 期望 %d", got, snapLen)
	}
	if got := r.LinkType(); got != layers.LinkTypeEthernet {
		t.Errorf("linktype=%v, 期望 ethernet", got)
	}
}

// TestWriteToPacketCount 验证写入的包数与时间戳。
func TestWriteToPacketCount(t *testing.T) {
	pkts := samplePackets()
	var buf bytes.Buffer
	if err := WriteTo(&buf, "ethernet", pkts); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	r, err := pcapgo.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("pcapgo reader: %v", err)
	}
	var got []gopacket.Packet
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		got = append(got, gopacket.NewPacket(raw, r.LinkType(), gopacket.Default))
	}
	if len(got) != len(pkts) {
		t.Fatalf("回读包数=%d, 期望 %d", len(got), len(pkts))
	}
}

// TestWriteToEmptyPackets 验证空包列表:只出文件头,无数据包(不报错)。
func TestWriteToEmptyPackets(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTo(&buf, "ethernet", nil); err != nil {
		t.Fatalf("空包列表不应报错,得到 %v", err)
	}
	// 应能读回文件头但无数据包。
	r, err := pcapgo.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("pcapgo reader: %v", err)
	}
	_, _, err = r.ReadPacketData()
	if err == nil {
		t.Error("空包列表不应有数据包")
	}
}

// TestWriteToUnknownLinkType 验证未知名 link_type 在写盘前即报错。
func TestWriteToUnknownLinkType(t *testing.T) {
	var buf bytes.Buffer
	err := WriteTo(&buf, "bogus", samplePackets())
	if err == nil {
		t.Fatal("未知名 link_type 应报错")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("错误应含未知名,得到 %v", err)
	}
}

// TestWriteErrorPath 验证 Write 的错误分支:指向不可写路径返回 error 而非 panic。
func TestWriteErrorPath(t *testing.T) {
	// 在临时目录下指向一个不存在的子目录的文件 → os.Create 失败。
	badPath := t.TempDir() + "/no-such-dir/out.pcap"
	err := Write(badPath, "ethernet", samplePackets())
	if err == nil {
		t.Fatal("不可写路径应返回 error")
	}
}
