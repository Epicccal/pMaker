package builder

import (
	"fmt"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// buildVXLAN 将 scenario 字段映射到 gopacket layers.VXLAN。
// VXLAN 头固定 8 字节(RFC 7348),无长度/checksum 语义,不开放长度覆盖;
// VNI 值域已由 scenario 校验拦截,此处防御性再查。
func buildVXLAN(f *scenario.VXLANFields) (*layers.VXLAN, error) {
	if f.VNI > 0xFFFFFF {
		return nil, fmt.Errorf("vxlan.vni 超出 24 位: %d", f.VNI)
	}
	v := &layers.VXLAN{VNI: f.VNI, ValidIDFlag: true} // 'I' 位缺省置位(规范头);显式 false 覆盖为非法头
	if f.ValidIDFlag != nil {
		v.ValidIDFlag = *f.ValidIDFlag
	}
	return v, nil
}
