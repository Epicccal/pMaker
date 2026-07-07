package writer

import (
	"fmt"
	"io"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/Epicccal/pMaker/internal/builder"
)

const snapLen = 65536

// linkType 把场景里的 link_type 名映射为 pcap 链路类型。
func linkType(name string) (layers.LinkType, error) {
	switch name {
	case "", "ethernet":
		return layers.LinkTypeEthernet, nil
	case "raw":
		return layers.LinkTypeRaw, nil
	case "ipv4":
		return layers.LinkTypeIPv4, nil
	default:
		return 0, fmt.Errorf("未知 link_type %q(支持 ethernet/raw/ipv4)", name)
	}
}

// Write 把数据包写入 path 指向的 pcap 文件。
func Write(path, linkTypeName string, pkts []builder.OutPacket) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteTo(f, linkTypeName, pkts)
}

// WriteTo 把数据包写入任意 io.Writer(便于测试逐字节比对)。
func WriteTo(w io.Writer, linkTypeName string, pkts []builder.OutPacket) error {
	lt, err := linkType(linkTypeName)
	if err != nil {
		return err
	}
	pw := pcapgo.NewWriter(w)
	if err := pw.WriteFileHeader(snapLen, lt); err != nil {
		return err
	}
	for _, p := range pkts {
		ci := gopacket.CaptureInfo{
			Timestamp:     p.Time,
			CaptureLength: len(p.Data),
			Length:        len(p.Data),
		}
		if err := pw.WritePacket(ci, p.Data); err != nil {
			return err
		}
	}
	return nil
}
