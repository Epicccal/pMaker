# icmp —— ICMPv4(控制/应用)

echo request/reply 及错误报文。`type`/`code` 可用名称或数字。

```yaml
- icmp:
    type: echo_request
    code: 0
    id: 0x0001
    seq: 1
    payload: "hello"
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `type` | 名称/数字 | 否 | 见下表;缺省 `echo_request`(8) |
| `code` | 名称/数字 | 否 | 缺省 0 |
| `id` | `Hex` | 否 | echo 的 Identifier |
| `seq` | uint16 | 否 | echo 的 Sequence |
| `payload` | string | 否 | 负载文本;与 `payload_hex`/`quote`/`quote_from` 互斥(只选一个) |
| `payload_hex` | `Hex` | 否 | 原始字节负载(`0x...`) |
| `quote` | packet | 否 | 错误报文内嵌的被引报文(以 `ipv4` 开头的完整 stack) |
| `quote_from` | string | 否 | 引用本 scenario 里另一个**具名 packet** 的 stack 作 quote |
| `gateway` | IPv4 | 否 | 仅 `redirect`(type 5):网关地址(bytes 4-7) |
| `pointer` | uint8 | 否 | 仅 `parameter_problem`(type 12):出错字节偏移(byte 4) |
| `mtu` | uint16 | 否 | 仅 `dest_unreachable` code 4:下一跳 MTU(RFC 1191) |
| `checksum` | `Hex` | 否 | 三态覆盖:不写=自动计算;写值=关闭自动计算,原样上 wire;`0` 也照单全收 |

## 已知 type 名称

`echo_reply`(0)、`destination_unreachable`(3)、`redirect`(5)、`echo_request`(8)、`time_exceeded`(11)、`parameter_problem`(12)。

## 已知 code 名称(部分)

destination_unreachable:`net_unreachable`(0)、`host_unreachable`(1)、`protocol_unreachable`(2)、`port_unreachable`(3)、`fragmentation_needed`(4)、`source_route_failed`(5)。time_exceeded:`ttl_exceeded`(0)、`fragment_reassembly_time_exceeded`(1)。

> `quote` 与 `quote_from` 只能配一个;`payload`/`payload_hex`/`quote`/`quote_from` 四选一。
