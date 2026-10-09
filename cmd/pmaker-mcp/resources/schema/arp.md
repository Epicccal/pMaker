# arp —— ARP 地址解析协议(L2.5,RFC 826)

构造 ARP(Address Resolution Protocol)数据包,用于 IPv4 over Ethernet 的 MAC 地址解析。
支持 Request / Reply / Gratuitous ARP / ARP Probe 及畸形包。通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "ff:ff:ff:ff:ff:ff" }
      - arp:
          operation: 1
          sender_hw_addr: "00:11:22:33:44:55"
          sender_proto_addr: "192.168.1.10"
          target_proto_addr: "192.168.1.1"
```

## 字段

| 字段 | 类型 | 缺省 | 说明 |
|------|------|------|------|
| `operation` | uint16 | **必填** | 1=Request, 2=Reply, 3=RARP Request, 4=RARP Reply |
| `target_proto_addr` | string(IPv4) | **必填** | 目标 IPv4 地址 |
| `sender_hw_addr` | string(MAC) | `00:00:00:00:00:00` | 发送方 MAC;须显式填写 |
| `sender_proto_addr` | string(IPv4) | `0.0.0.0` | 发送方 IPv4 |
| `target_hw_addr` | string(MAC) | `00:00:00:00:00:00` | 目标 MAC;Request 通常全零 |
| `hardware_type` | uint16 | `1` | 硬件类型(1=Ethernet);覆盖以构造非标类型 |
| `protocol_type` | uint16 | `0x0800` | 协议类型;覆盖以构造非 IP ARP |
| `hardware_length` | uint8 | `6` | 硬件地址长度;写不匹配值产 `arp.length-mismatch` 告警 |
| `protocol_length` | uint8 | `4` | 协议地址长度;写不匹配值产 `arp.length-mismatch` 告警 |

不提供 `_raw` 地址字段:长度不匹配畸形走 `hardware_length`/`protocol_length` 覆盖;
非标字节内容省去 `arp` 层,整段用 `payload_hex` 手拼(与 `eth` 畸形模式一致)。

## 组合规则

- **前置层**:`eth`(EtherType 自动设为 `0x0806`)或 `vlan`(内层同理)
- **后续层**:通常无(终结层);允许 `payload` / `payload_hex` 用于构造非标包
- ARP 不包含 IP 层,stack 顺序应为 `eth → arp`,不能是 `eth → ipv4 → arp`(校验报硬错)

## 软告警

| Code | 触发条件 |
|------|---------|
| `arp.gratuitous` | `sender_proto_addr == target_proto_addr` |
| `arp.probe` | `sender_proto_addr == 0.0.0.0`(RFC 5227 冲突检测);省略该字段同样按 `0.0.0.0` 判定 |
| `arp.request-non-zero-target-hw` | `operation=1` 但 `target_hw_addr` 非全零 |
| `arp.length-mismatch` | `hardware_length`/`protocol_length` 与地址字段实际长度不符 |

告警按字段缺省填充后的线上值判定,不按声明文本:省略 `sender_proto_addr` 与显式写
`0.0.0.0` 落线逐位相同,告警也相同。

## 示例

### ARP Request

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "ff:ff:ff:ff:ff:ff" }
      - arp:
          operation: 1
          sender_hw_addr: "00:11:22:33:44:55"
          sender_proto_addr: "192.168.1.10"
          target_proto_addr: "192.168.1.1"
```

### ARP Reply

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:0c:29:aa:bb:cc", dst: "00:0c:29:12:34:56" }
      - arp:
          operation: 2
          sender_hw_addr: "00:0c:29:aa:bb:cc"
          sender_proto_addr: "192.168.1.1"
          target_hw_addr: "00:0c:29:12:34:56"
          target_proto_addr: "192.168.1.10"
```

### Gratuitous ARP

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:0c:29:12:34:56", dst: "ff:ff:ff:ff:ff:ff" }
      - arp:
          operation: 2
          sender_hw_addr: "00:0c:29:12:34:56"
          sender_proto_addr: "192.168.1.100"
          target_proto_addr: "192.168.1.100"
```

### 畸形:非法 operation

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "ff:ff:ff:ff:ff:ff" }
      - arp:
          operation: 0xdead
          sender_hw_addr: "00:11:22:33:44:55"
          sender_proto_addr: "10.0.0.1"
          target_proto_addr: "10.0.0.2"
```

### 畸形:长度字段不匹配

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "aa:bb:cc:dd:ee:ff", dst: "ff:ff:ff:ff:ff:ff" }
      - arp:
          operation: 1
          hardware_length: 8
          protocol_length: 6
          sender_hw_addr: "aa:bb:cc:dd:ee:ff"
          sender_proto_addr: "192.168.1.1"
          target_proto_addr: "192.168.1.2"
```

### ARP 欺骗场景（授权测试 / 防御验证）

ARP 欺骗的核心：`sender_hw_addr` 与 `sender_proto_addr` 无需与 `eth.src` 一致，
攻击者可以宣称任意 IP 对应自己的 MAC，覆盖受害者的 ARP 缓存。
三包构成完整上下文：合法宣告 → 伪造投毒 → 受害者流量被劫持。

```yaml
link_type: ethernet
packets:
  # 1. 合法方广播：IPA(192.168.1.1) 宣告自己的 MAC 是 MACA
  - name: legitimate-garp
    stack:
      - eth:  { src: "aa:aa:aa:aa:aa:aa", dst: "ff:ff:ff:ff:ff:ff" }
      - arp:
          operation: 2
          sender_hw_addr: "aa:aa:aa:aa:aa:aa"
          sender_proto_addr: "192.168.1.1"
          target_hw_addr: "00:00:00:00:00:00"
          target_proto_addr: "192.168.1.1"

  # 2. 攻击者伪造 Reply：声称 IPA 对应 MACB，覆盖受害者 ARP 缓存
  - name: poison-reply
    stack:
      - eth:  { src: "bb:bb:bb:bb:bb:bb", dst: "ff:ff:ff:ff:ff:ff" }
      - arp:
          operation: 2
          sender_hw_addr: "bb:bb:bb:bb:bb:bb"   # 攻击者 MAC 伪装成 IPA 的拥有者
          sender_proto_addr: "192.168.1.1"       # 声称持有 IPA
          target_hw_addr: "00:00:00:00:00:00"
          target_proto_addr: "192.168.1.1"

  # 3. 受害者缓存已中毒：发往 IPA 的帧 eth.dst 变成了 MACB
  - name: victim-traffic-hijacked
    stack:
      - eth:  { src: "cc:cc:cc:cc:cc:cc", dst: "bb:bb:bb:bb:bb:bb" }
      - ipv4: { src: "192.168.1.100", dst: "192.168.1.1", ttl: 64 }
      - tcp:  { sport: 54321, dport: 80, flags: [SYN] }
```

前两个包会触发 `arp.gratuitous` 软告警（`sender_proto_addr == target_proto_addr`），
这是正常现象，不影响生成，符合场景语义。

## 相关

- RFC 826 — ARP
- RFC 5227 — IPv4 Address Conflict Detection(Gratuitous ARP / ARP Probe)
