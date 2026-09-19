# icmpv6 —— ICMPv6(控制报文)

echo 与错误报文。校验和依赖 **IPv6 伪首部**(builder 自动绑就近 IPv6)。
通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:    { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv6:   { src: "2001:db8::1", dst: "2001:db8::2", hop_limit: 64 }
      - icmpv6: { type: echo_request, code: 0, id: 0x0001, seq: 1, payload: "hello" }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `type` | 名称 / 数字 | 否 | 缺省 `echo_request`(128) |
| `code` | 名称 / 数字 | 否 | 缺省 0 |
| `id` | `Hex` | 否 | Identifier,**仅 echo(128/129)** |
| `seq` | uint16 | 否 | Sequence,**仅 echo(128/129)** |
| `payload` | string | 否 | 负载文本;与 `payload_hex` / `quote` / `quote_from` **四选一** |
| `payload_hex` | string | 否 | `0x…` 原始字节负载 |
| `quote` | packet | 否 | 内嵌被引报文,`stack` **须以 `ipv6` 开头** |
| `quote_from` | string | 否 | 引用本 scenario 里另一个具名 packet 的 IPv6 部分 |
| `mtu` | uint32 | 否 | **仅 `packet_too_big`(2)**:下一跳 MTU |
| `pointer` | uint32 | 否 | **仅 `parameter_problem`(4)**:出错字节偏移 |
| `checksum` | `Hex` | 否 | 两态覆盖:不写=自动计算(绑 IPv6 伪首部);写值=原样上 wire |

**已知 type 名**:`destination_unreachable`(1)、`packet_too_big`(2)、`time_exceeded`(3)、
`parameter_problem`(4)、`echo_request`(128)、`echo_reply`(129)。

**已知 code 名**:destination_unreachable 用 `no_route`(0)、`admin_prohibited`(1)、
`beyond_scope`(2)、`address_unreachable`(3)、`port_unreachable`(4)、`src_policy_failed`(5)、
`reject_route`(6);time_exceeded 用 `hop_limit_exceeded`(0)、
`fragment_reassembly_time_exceeded`(1);parameter_problem 用 `erroneous_header_field`(0)、
`unrecognized_next_header`(1)、`unrecognized_ipv6_option`(2)。名字之外也接受任意数字。

## 组合规则(硬错)

- `payload` / `payload_hex` / `quote` / `quote_from` 至多一个。
- `quote.stack` 非空且**以 `ipv6` 开头**。
- `id` / `seq` 仅 echo 可用;`mtu` 仅 type 2、`pointer` 仅 type 4(错配在出包阶段报错)。
- 上层必须是 `ipv6`:next-header 自动推导为 58,且校验和要 IPv6 伪首部。

## 静默陷阱

- **放在 `ipv4` 下面不会被拦**。`ipv4` + `icmpv6` 的组合能生成:IP protocol 会被推成 58,
  校验和用 IPv4 伪首部算 —— 出来的是无意义的包,不报错不告警。
- **错误报文自动插 4 字节 reserved 字段**(RFC 4443 §3),位于 ICMPv6 头与 quote 之间;
  没写 `mtu` / `pointer` 时它是全 0。手工按字节数对照 wire 时别漏了这 4 字节。
- **`port_unreachable` 在 ICMPv6 里是 4,在 ICMPv4 里是 3**。code 名字表两边不通用,
  照抄 ICMPv4 的 YAML 会得到不同的数值,且不会有任何提示。
- `quote` 不做 RFC 截断(自动截取只在 `quote_from` 路径),与 ICMPv4 同。
- **`quote_from` 复用被引包的真实 wire 首片字节**(自栈序第一个 `ipv6` 层头起,
  按 RFC 4443 §2.4(c) 截到 1232 字节上限):与 pcap 里逐字节一致 —— 被引包带
  `mtu` 分片时,quote 就取自分片首片(含分片 ID)。**被引包必须排在引用之前的
  时刻**,前向引用在出包阶段硬错;引用环在校验阶段报
  `quote_from 引用环: a → b → a`。
- `quote.stack` 内禁写 `mtu`(quote 是载荷提取视图,恒取单片)。
- Neighbor Discovery(NS/NA/RS/RA,type 133-137)**未实现结构化字段**:能写 `type: 135`,
  但选项(target address、link-layer address)只能用 `payload_hex` 手拼。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 错误校验和 | `checksum: 0xdead` |
| 未分配 / 保留的 type-code | `type: 200, code: 99` |
| 超长 quote | `quote: { stack: [...] }` |
| ND 报文(NS/NA/RA) | `type: 135` + `payload_hex` 手拼选项 |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `quote/quote_from/payload/payload_hex 只能配置一个` | 四选一。要在 quote 后追加字节,整段拼成 `payload_hex` |
| `quote.stack 目前必须以 ipv6 开头` | ICMPv6 的 quote 从 IPv6 头开始,不带以太头,也不能是 `ipv4` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv6:   { src: "2001:db8::1", dst: "2001:db8::2" }
      - icmpv6:
          type: echo_request
          payload: "hi"
          payload_hex: "0xdead"
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv6:   { src: "2001:db8::1", dst: "2001:db8::2" }
      - icmpv6:
          type: packet_too_big
          mtu: 1280
          quote:
            stack:
              - ipv4: { src: "10.0.0.2", dst: "10.0.0.1" }
              - udp:  { sport: 1, dport: 2 }
```

## 相关

`pmaker://schema/icmp`(ICMPv4)、`pmaker://schema/ipv6`
