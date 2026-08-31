# icmpv6 —— ICMPv6(控制/应用)

echo 及错误报文。校验和依赖 IPv6 伪首部(builder 自动绑定)。

```yaml
- icmpv6:
    type: echo_request
    code: 0
    id: 0x0001
    seq: 1
    payload: "hello"
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `type` | 名称/数字 | 否 | 见下表 |
| `code` | 名称/数字 | 否 | 缺省 0 |
| `id` | `Hex` | 否 | echo 的 Identifier(仅 echo) |
| `seq` | uint16 | 否 | echo 的 Sequence(仅 echo) |
| `payload` | string | 否 | 负载文本;与 `payload_hex`/`quote`/`quote_from` 互斥 |
| `payload_hex` | `Hex` | 否 | 原始字节负载 |
| `quote` | packet | 否 | 错误报文内嵌的被引报文(以 `ipv6` 开头的完整 stack) |
| `quote_from` | string | 否 | 引用本 scenario 里另一个具名 packet 的 stack 作 quote |
| `mtu` | uint32 | 否 | 仅 `packet_too_big`(type 2):下一跳 MTU |
| `pointer` | uint32 | 否 | 仅 `parameter_problem`(type 4):出错字节偏移 |
| `checksum` | `Hex` | 否 | 两态覆盖:不写=自动计算(伪首部绑就近 IPv6);写值=关闭自动计算,原样上 wire;`0` 也照单全收 |

## 已知 type 名称

`packet_too_big`(2)、`time_exceeded`(3)、`parameter_problem`(4)、`echo_request`(128)、`echo_reply`(129)。

> `id`/`seq` 仅 echo 可用;`mtu` 仅 packet_too_big、`pointer` 仅 parameter_problem。
