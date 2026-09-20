package builder

import (
	"fmt"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// OutPacket 是构造好的一个数据包:字节 + 确定性时间戳 + 来源信息。
// 来源信息供 summary 按分片展开(frag k/N):未分片 K/N 恒为 1/1。
type OutPacket struct {
	Data []byte
	Time time.Time
	// Frag 是分片来源信息:所属 PlannedPacket 在排序列表中的下标、本片序号 k(0 起)、
	// 该包总分片数 N。分片各片共享原包 Time,Time 列不区分片,frag 列区分。
	Frag FragInfo
}

// FragInfo 记录一个 OutPacket 与其来源 PlannedPacket 的分片关系。
type FragInfo struct {
	PlannedIdx int
	K          int // 0 起
	N          int // >= 1;未分片恒 1
}

// defaultSerOpts 是各层 SerializeOptions 的模板:统一修正长度并计算 checksum。
// per-layer 覆盖时拷贝一份再按需关掉 ComputeChecksums(见 buildSerItems 的 add 闭包)。
var defaultSerOpts = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

// packetWire 是一个命名 packet 的 wire 结果快照:quote_from 复用被引包
// 已产出的字节,不再二次序列化 —— 分片 ID、ICMP quote 内嵌 IP 头与 pcap
// 首片因此天然逐字节一致。
type packetWire struct {
	// IP4Down / IP6Down 是首片自「栈序第一个同族 IP 层头」起的字节快照(在该层
	// SerializeTo 完成的瞬间拷贝,不含外层 eth 补的帧尾 padding);被引栈无对应族
	// IP 层则 nil。
	// 起点必须是栈序第一个同族层(不是反向序列化循环里最先完成的那个 —— 反向由内
	// 向外,最先完成的是最内层同族 IP,记错层 quote 逐字节全错)。
	IP4Down []byte
	IP6Down []byte
}

type buildContext struct {
	packetsByName map[string]scenario.Packet
	// results 是命名 packet 的 wire 结果快照,随单次 BuildPlanned 生死,
	// 场景级隔离,不引入全局状态(设计约束 6)。quote_from 查此表;未命中 = 被引包
	// 排在引用包之后(前向引用),由 icmpQuoteFrom / icmpv6QuoteFrom 报带包名的硬错。
	results map[string]*packetWire
	// ipID 是分片 ID 确定性计数器:每次 BuildPlanned 从 0 起,只在数据报
	// 真正被分片时递增;同一数据报各片共用(IPv4 16 位 Id / IPv6 32 位 Identification)。
	ipID uint32
}

// stackHasQuoteFrom 判断层栈是否含 quote_from 引用(递归下钻 quote.stack)。
// ip-down 快照只有 quote_from 消费;场景里一个引用都没有时全程跳过快照,
// 纯流量场景(多包 × 多层 IP 隧道)不为每层 IP 白做一次全帧拷贝。
// 必须预扫而不能"遇首个 quote_from 再启用":引用要求被引包先于引用包序列化,
// 等看到引用时被引包的快照时机早已错过。
func stackHasQuoteFrom(stack []scenario.Layer) bool {
	for _, l := range stack {
		var from string
		var quote *scenario.Packet
		switch f := l.Fields.(type) {
		case *scenario.ICMPFields:
			from, quote = f.QuoteFrom, f.Quote
		case *scenario.ICMPv6Fields:
			from, quote = f.QuoteFrom, f.Quote
		default:
			continue
		}
		if from != "" {
			return true
		}
		if quote != nil && stackHasQuoteFrom(quote.Stack) {
			return true
		}
	}
	return false
}

// BuildPlanned 把已汇流排序的 PlannedPacket 逐包序列化为字节;
// 时间戳取自每个 PlannedPacket.Time(由 internal/plan 分配)。
// 分片把一个 PlannedPacket 展开成 1..N 个 OutPacket(各片与原包同刻);
// 命名 packet 的结果写入 ctx.results 供 quote_from 命中。
func BuildPlanned(planned []scenario.PlannedPacket) ([]OutPacket, error) {
	wantWire := false
	for _, pp := range planned {
		if stackHasQuoteFrom(pp.Stack) {
			wantWire = true
			break
		}
	}
	ctx := &buildContext{
		packetsByName: plannedByName(planned),
		results:       map[string]*packetWire{},
	}
	out := make([]OutPacket, 0, len(planned))
	for i, pp := range planned {
		// 只有会被 quote_from 消费的包(具名,且场景确实存在引用)才拍 ip-down 快照;
		// 其余包 down4/down6 恒 nil,序列化循环跳过每次 IP 层后的全帧拷贝。
		frames, down4, down6, err := serializeStack(ctx, pp.Stack, wantWire && pp.Name != "")
		if err != nil {
			name := pp.Name
			if name == "" {
				name = fmt.Sprintf("packet[%d]", i)
			}
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		for k, frame := range frames {
			out = append(out, OutPacket{Data: frame, Time: pp.Time, Frag: FragInfo{PlannedIdx: i, K: k, N: len(frames)}})
		}
		// quote_from 快照:只记具名包。被引包须排在引用之前的时刻
		// (默认声明顺序即满足),未命中在 quote 侧报前向引用硬错。
		if pp.Name != "" {
			ctx.results[pp.Name] = &packetWire{IP4Down: down4, IP6Down: down6}
		}
	}
	return out, nil
}

// plannedByName 收集具名 packet(quote_from 引用要求唯一,重名由校验拦截)。
func plannedByName(planned []scenario.PlannedPacket) map[string]scenario.Packet {
	out := map[string]scenario.Packet{}
	for _, pp := range planned {
		if pp.Name != "" {
			out[pp.Name] = pp.Packet
		}
	}
	return out
}

// serItem 是序列化循环的一项:层对象 + 该层 SerializeOptions + 长度覆盖信息。
// scenario 层经 buildSerItems 的 add 逐项展开;预构建层(分片重建栈的目标 IP 层
// 变体、IPv6 Fragment 扩展头、原始 Payload 块)直接构造 serItem 加入,
// 绕过 scenario → layer 的重推导(混合栈旁路)。
type serItem struct {
	layer   gopacket.SerializableLayer
	opts    gopacket.SerializeOptions
	lenFill lengthOverrideInfo
}

// wireResult 是 serializeStack 的一次产出:逐片整帧 + 首片的两个 ip-down 切片。
type wireResult struct {
	frames [][]byte
	down4  []byte
	down6  []byte
}

// serializeStack 把一个有序层栈序列化为 1..N 帧字节:未分片时 1 帧;目标 IP 层
// 写了 mtu 且数据报超限时逐片一帧(各片与原包同刻,由调用方赋 Time)。
// down4/down6 是首片自栈序第一个同族 IP 层头起的切片(无该族层则 nil),供
// quote_from 快照;wantWire=false 时全程不拍快照,返回 nil。
func serializeStack(ctx *buildContext, stack []scenario.Layer, wantWire bool) ([][]byte, []byte, []byte, error) {
	items, target, err := buildSerItems(ctx, stack)
	if err != nil {
		return nil, nil, nil, err
	}
	if target == nil {
		res, err := serializeItems(items, wantWire)
		if err != nil {
			return nil, nil, nil, err
		}
		return res.frames, res.down4, res.down6, nil
	}
	// 目标 IP 层的载荷 = 该层以内(items[target.idx+1:])的全部字节。只序列化内层
	// 部分即可拿到:L4 checksum 在构建期已绑就近 IP 层,此时基于完整数据报算出 ——
	// 正是分片要的正确值(各片共享的 L4 头校验和本就应覆盖重组后的完整数据报)。
	inner, err := serializeItems(items[target.idx+1:], false)
	if err != nil {
		return nil, nil, nil, err
	}
	// 未超限判断用「未分片数据报」的头长:ipv6 = 40(主头,未分片无 Fragment 扩展头)。
	// 分片路径(fragmentFrames)的每片头是 40+8 —— 两处口径有意不同,不要"同步"。
	headerLen := 40
	if target.family == "ipv4" {
		headerLen = 20 + ipv4OptionSize(target.v4)
	}
	if headerLen+len(inner.frames[0]) <= target.mtu {
		// 未超限:照常完成,不动任何字段,出一个包。
		res, err := serializeItems(items, wantWire)
		if err != nil {
			return nil, nil, nil, err
		}
		return res.frames, res.down4, res.down6, nil
	}
	// 超限:逐片重建「目标层片变体 + Payload(块)」,再拼上外层(items[:target.idx])
	// 原样复用 —— gopacket FixLengths 下层对象重复序列化安全,外层 IP/UDP 的长度
	// 与 checksum 逐片自动重算,隧道嵌套免费正确。
	fragItems, err := fragmentFrames(ctx, target, inner.frames[0])
	if err != nil {
		return nil, nil, nil, err
	}
	var res *wireResult
	frames := make([][]byte, len(fragItems))
	for k, fi := range fragItems {
		full := make([]serItem, 0, target.idx+len(fi))
		full = append(full, items[:target.idx]...)
		full = append(full, fi...)
		r, err := serializeItems(full, wantWire && k == 0)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("分片 %d/%d: %w", k+1, len(fragItems), err)
		}
		frames[k] = r.frames[0]
		if k == 0 {
			res = r // 首片的 ip-down 切片即 quote 取材口径(quote = wire 首片)
		}
	}
	return frames, res.down4, res.down6, nil
}

// buildSerItems 把 scenario 层栈展开为 serItem 列表(外到内),并定位 mtu 分片目标层
// (写了 mtu 的那层 IP;校验保证一个 stack 至多一层)。next-proto 推导、checksum
// 伪首部就近绑定、两态覆盖都在这里完成。
func buildSerItems(ctx *buildContext, stack []scenario.Layer) ([]serItem, *fragTarget, error) {
	items := make([]serItem, 0, len(stack))
	var target *fragTarget
	// items 每项自带该层的 SerializeOptions 与长度覆盖标志。
	// 默认 = defaultSerOpts(自动修正长度 + 计算 checksum);显式覆盖时拷贝一份按需关掉。
	// 索引必须跟着 items 走:ICMPv6 一个 scenario 层会 append 出 icmp/echo/reserved/payload
	// 多项,每项都要配对,故统一走 add,不在 switch 外零散 append。
	add := func(l gopacket.SerializableLayer, csum *scenario.Hex, info lengthOverrideInfo) {
		o := defaultSerOpts
		if csum != nil {
			o.ComputeChecksums = false
		}
		if info.any() {
			o.FixLengths = false
		}
		items = append(items, serItem{layer: l, opts: o, lenFill: info})
	}
	var netLayer gopacket.NetworkLayer // 最近的 IP 层,供传输层 checksum 伪首部使用

	for j, l := range stack {
		next := ""
		if j+1 < len(stack) {
			next = stack[j+1].Type
		}

		switch f := l.Fields.(type) {
		case *scenario.EthFields:
			eth, err := buildEth(f, next)
			if err != nil {
				return nil, nil, fmt.Errorf("eth: %w", err)
			}
			add(eth, nil, lengthOverrideInfo{})
		case *scenario.VLANFields:
			vlan, err := buildVLAN(f, next)
			if err != nil {
				return nil, nil, fmt.Errorf("vlan: %w", err)
			}
			add(vlan, nil, lengthOverrideInfo{})
		case *scenario.IPv4Fields:
			ip, err := buildIPv4(f, next)
			if err != nil {
				return nil, nil, fmt.Errorf("ipv4: %w", err)
			}
			netLayer = ip
			add(ip, f.Checksum, lengthOverrideInfo{ipv4Length: f.Length, ipv4IHL: f.IHL})
			if f.MTU > 0 {
				target = &fragTarget{idx: len(items) - 1, family: "ipv4", mtu: f.MTU, v4: ip}
			}
		case *scenario.IPv6Fields:
			ip, err := buildIPv6(f, next)
			if err != nil {
				return nil, nil, fmt.Errorf("ipv6: %w", err)
			}
			netLayer = ip
			add(ip, nil, lengthOverrideInfo{ipv6PayloadLength: f.PayloadLength})
			if f.MTU > 0 {
				target = &fragTarget{idx: len(items) - 1, family: "ipv6", mtu: f.MTU, v6: ip, nextHeader: ip.NextHeader}
			}
		case *scenario.GREFields:
			gre, err := buildGRE(next)
			if err != nil {
				return nil, nil, fmt.Errorf("gre: %w", err)
			}
			add(gre, nil, lengthOverrideInfo{})
		case *scenario.VXLANFields:
			// VXLAN 不是 IP 网络层,不更新 netLayer:外层 UDP 已绑定外层 IP,
			// 内层 TCP/UDP 绑定之后遇到的最近内层 IP(与 GRE 内层同机制)。
			vxlan, err := buildVXLAN(f)
			if err != nil {
				return nil, nil, fmt.Errorf("vxlan: %w", err)
			}
			add(vxlan, nil, lengthOverrideInfo{})
		case *scenario.TCPFields:
			t, err := buildTCP(f)
			if err != nil {
				return nil, nil, fmt.Errorf("tcp: %w", err)
			}
			if netLayer != nil {
				_ = t.SetNetworkLayerForChecksum(netLayer)
			}
			add(t, f.Checksum, lengthOverrideInfo{tcpDataOffset: f.DataOffset})
		case *scenario.UDPFields:
			u := buildUDP(f)
			if netLayer != nil {
				_ = u.SetNetworkLayerForChecksum(netLayer)
			}
			add(u, f.Checksum, lengthOverrideInfo{udpLength: f.Length})
		case *scenario.ICMPFields:
			icmp, payload, err := buildICMP(ctx, f)
			if err != nil {
				return nil, nil, fmt.Errorf("icmp: %w", err)
			}
			add(icmp, f.Checksum, lengthOverrideInfo{})
			if len(payload) > 0 {
				add(gopacket.Payload(payload), nil, lengthOverrideInfo{})
			}
		case *scenario.ICMPv6Fields:
			icmp, echo, reserved, payload, err := buildICMPv6(ctx, f)
			if err != nil {
				return nil, nil, fmt.Errorf("icmpv6: %w", err)
			}
			// ICMPv6 校验和依赖 IPv6 伪首部;就近绑定最近的 IP 层(内层 IPv6)。
			if netLayer != nil {
				if err := icmp.SetNetworkLayerForChecksum(netLayer); err != nil {
					return nil, nil, fmt.Errorf("icmpv6: %w", err)
				}
			}
			add(icmp, f.Checksum, lengthOverrideInfo{})
			if echo != nil {
				add(echo, nil, lengthOverrideInfo{})
			}
			// 错误报文(非 echo)的 4 字节类型相关字段,置于 ICMPv6 头与 quote 之间。
			// 作为独立 Payload 层,gopacket 的 ICMPv6 checksum 会自动将其纳入计算。
			if len(reserved) > 0 {
				add(gopacket.Payload(reserved), nil, lengthOverrideInfo{})
			}
			if len(payload) > 0 {
				add(gopacket.Payload(payload), nil, lengthOverrideInfo{})
			}
		case *scenario.PayloadFields:
			b, err := payloadBytes(f)
			if err != nil {
				return nil, nil, fmt.Errorf("payload: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case scenario.PayloadHex:
			b, err := scenario.ParsePayloadHex(string(f))
			if err != nil {
				return nil, nil, fmt.Errorf("payload_hex: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.DNSFields:
			d, err := buildDNS(f)
			if err != nil {
				return nil, nil, fmt.Errorf("dns: %w", err)
			}
			add(d, nil, lengthOverrideInfo{})
		case *scenario.TFTPFields:
			b, err := serializeTFTP(f)
			if err != nil {
				return nil, nil, fmt.Errorf("tftp: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.HTTPReqFields:
			b, err := serializeHTTPReq(f)
			if err != nil {
				return nil, nil, fmt.Errorf("http_request: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.HTTPRespFields:
			b, err := serializeHTTPResp(f)
			if err != nil {
				return nil, nil, fmt.Errorf("http_response: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.FTPRequestFields:
			add(gopacket.Payload(serializeFTPReq(f)), nil, lengthOverrideInfo{})
		case *scenario.FTPResponseFields:
			add(gopacket.Payload(serializeFTPResp(f)), nil, lengthOverrideInfo{})
		case *scenario.TelnetFields:
			b, err := serializeTelnet(f)
			if err != nil {
				return nil, nil, fmt.Errorf("telnet: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.SMTPRequestFields:
			add(gopacket.Payload(serializeSMTPReq(f)), nil, lengthOverrideInfo{})
		case *scenario.SMTPResponseFields:
			add(gopacket.Payload(serializeSMTPResp(f)), nil, lengthOverrideInfo{})
		case *scenario.POP3RequestFields:
			add(gopacket.Payload(serializePOP3Req(f)), nil, lengthOverrideInfo{})
		case *scenario.POP3ResponseFields:
			b, err := serializePOP3Resp(f)
			if err != nil {
				return nil, nil, fmt.Errorf("pop3_response: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.IMAPRequestFields:
			b, err := serializeIMAPReq(f)
			if err != nil {
				return nil, nil, fmt.Errorf("imap_request: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.IMAPResponseFields:
			b, err := serializeIMAPResp(f)
			if err != nil {
				return nil, nil, fmt.Errorf("imap_response: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.EMLDataFields:
			b, err := serializeEMLDataFramed(f)
			if err != nil {
				return nil, nil, fmt.Errorf("eml_data: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		default:
			return nil, nil, fmt.Errorf("不支持的层类型 %q", l.Type)
		}
	}
	return items, target, nil
}

// serializeItems 跑自写逐层序列化循环(等价于 gopacket.SerializeLayers,但允许每层
// 用不同 opts)。反向(从最内层到最外层)依次 PrependBytes,与 SerializeLayers 行为一致。
//
// ip-down 就地快照:每个 IP 层 SerializeTo 完成的瞬间,buf.Bytes() 恰为
// 「该层头起、到当前缓冲区末尾」的全部字节 —— 正是 ip-down 视图,此刻取拷贝;
// 同族后完成的是更外层,最终定格在栈序第一个同族 IP 层。不能等整帧完成后再按
// 偏移切最终帧:外层 eth 会往帧尾补 padding(最小 60 字节帧),帧尾锚点会漂移;
// 也不由层头长静态累计(TCP options 等动态头长会让静态口径出错)。
//
// wantWire=false 时跳过快照拷贝:down4/down6 只被 quote_from 消费,调用方已知
// 本次序列化不会被引用时,纯转发/隧道流量不为每层 IP 白做一次全帧拷贝。
func serializeItems(items []serItem, wantWire bool) (*wireResult, error) {
	buf := gopacket.NewSerializeBuffer()
	if err := buf.Clear(); err != nil {
		return nil, fmt.Errorf("清空序列化缓冲区: %w", err)
	}
	var down4, down6 []byte
	for i := len(items) - 1; i >= 0; i-- {
		// SerializeTo 之前补值:此时 buf.Bytes() 是该层 payload(尚未 prepend 本层头),
		// 与 gopacket 内部取值时机一致。只对有覆盖的层(info.any())补未覆盖字段为公式值;
		// 覆盖字段(含显式 0)原样落值,不碰。
		if err := fillLengths(items[i].layer, items[i].lenFill, buf); err != nil {
			return nil, fmt.Errorf("序列化层 %d(%s): %w", i, items[i].layer.LayerType(), err)
		}
		if err := items[i].layer.SerializeTo(buf, items[i].opts); err != nil {
			// 索引 i 是 serItems 的位置(由外到内),与 stack 非一一对应
			// (ICMPv6 一个 scenario 层会展开多项),故用 gopacket LayerType 定位。
			return nil, fmt.Errorf("序列化层 %d(%s): %w", i, items[i].layer.LayerType(), err)
		}
		if wantWire {
			switch items[i].layer.(type) {
			case *layers.IPv4:
				down4 = append([]byte(nil), buf.Bytes()...)
			case *layers.IPv6:
				down6 = append([]byte(nil), buf.Bytes()...)
			}
		}
		buf.PushLayer(items[i].layer.LayerType())
	}
	return &wireResult{frames: [][]byte{buf.Bytes()}, down4: down4, down6: down6}, nil
}
