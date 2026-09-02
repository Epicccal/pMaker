# icmp —— ICMPv4(控制报文)

echo request/reply 与错误报文(内嵌被引报文 quote)。`type` / `code` 可写名称或数字。
通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - icmp: { type: echo_request, code: 0, id: 0x0001, seq: 1, payload: "hello" }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `type` | 名称 / 数字 | 否 | 缺省 `echo_request`(8) |
| `code` | 名称 / 数字 | 否 | 缺省 0 |
| `id` | `Hex` | 否 | Identifier,**仅 echo(0/8)** |
| `seq` | uint16 | 否 | Sequence,**仅 echo(0/8)** |
| `payload` | string | 否 | 负载文本;与 `payload_hex` / `quote` / `quote_from` **四选一** |
| `payload_hex` | string | 否 | `0x…` 原始字节负载 |
| `quote` | packet | 否 | 内嵌被引报文,`stack` **须以 `ipv4` 开头** |
| `quote_from` | string | 否 | 引用本 scenario 里另一个**具名 packet**,自动按 RFC 792 截取(IP 头 + 8 字节) |
| `gateway` | IPv4 字符串 | 否 | **仅 `redirect`(5)**:网关地址(bytes 4-7) |
| `pointer` | uint8 | 否 | **仅 `parameter_problem`(12)**:出错字节偏移(byte 4) |
| `mtu` | uint16 | 否 | **仅 `destination_unreachable`(3) code 4**:下一跳 MTU(RFC 1191) |
| `checksum` | `Hex` | 否 | 两态覆盖:不写=自动计算;写值=原样上 wire |

**已知 type 名**:`echo_reply`(0)、`destination_unreachable`(3)、`redirect`(5)、
`echo_request`(8)、`time_exceeded`(11)、`parameter_problem`(12)。

**已知 code 名**:`net_unreachable`(0)、`host_unreachable`(1)、`protocol_unreachable`(2)、
`port_unreachable`(3)、`fragmentation_needed`(4)、`source_route_failed`(5);
time_exceeded 用 `ttl_exceeded`(0)、`fragment_reassembly_time_exceeded`(1)。

名字之外**也接受任意数字**(`type: 13`),这点与 `ipv4.protocol` 不同 —— 未知**名字**才报错。

## 组合规则(硬错)

- `payload` / `payload_hex` / `quote` / `quote_from` 至多一个。
- `quote.stack` 非空且**以 `ipv4` 开头**(不是 `eth`)。
- `id` / `seq` **只有 echo 能用**;非 echo 类型写了会在出包阶段报 `id/seq 仅支持 echo_request/echo_reply`。
- `gateway` / `pointer` / `mtu` 与 type 严格绑定,错配在出包阶段报错。
- ICMP 的 IP protocol 自动推导为 1,无需写 `ipv4.protocol`。

## 静默陷阱

- **type / code 的数字不做语义校验**:`type: 200`、`code: 99` 照单全收(这是有意的畸形构造能力),
  但拼错的名字(`echo-request`)会**报错**而不是静默降级。
- **`quote` 的内容不被截断**:写多长就带多长,不会按 RFC 792 截到"IP 头 + 8 字节"。
  自动截取只发生在 **`quote_from`** 路径上。要构造超长 quote 就用 `quote`。
- `code` 名字表是**跨 type 共用**的一张扁平表:`ttl_exceeded` 与 `net_unreachable` 都是 0,
  写串了不会报错。数字更不会错。
- ICMPv4 **没有伪首部**(与 ICMPv6 不同),校验和只覆盖 ICMP 报文本身。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 错误校验和 | `checksum: 0xdead` |
| 未分配 / 保留的 type-code | `type: 200, code: 99`(数字直接写) |
| 超长 / 内容不符的 quote | `quote: { stack: [...] }` 自己写多长写多长 |
| 引用真实触发包的规范 quote | `quote_from: "<packet 的 name>"` |
| type 相关字段错配(如 echo 带 mtu) | 无法结构化构造(硬错),走 `payload_hex` |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `quote/quote_from/payload/payload_hex 只能配置一个` | 四选一。要在 quote 后再追加字节,把整段拼成 `payload_hex` |
| `quote.stack 目前必须以 ipv4 开头` | quote 是"被引报文的 IP 部分",不带以太头。把 `- eth: {...}` 从 quote 里删掉 |
| `quote.stack 不能为空` | `quote: {}` 不合法;不需要 quote 就整个删掉这个字段 |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - icmp:
          type: echo_request
          payload: "hi"
          payload_hex: "0xdead"
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - icmp:
          type: destination_unreachable
          code: port_unreachable
          quote:
            stack:
              - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
              - ipv4: { src: "10.0.0.2", dst: "10.0.0.1" }
              - udp:  { sport: 1, dport: 2 }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - icmp:
          type: time_exceeded
          quote: {}
```

## 相关

`pmaker://schema/icmpv6`、`pmaker://schema/ipv4`、`pmaker://schema/payload_hex`
