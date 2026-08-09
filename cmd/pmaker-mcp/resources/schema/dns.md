# dns —— DNS(L7,通常走 udp)

```yaml
- udp: { sport: 5353, dport: 53 }
- dns:
    id: 0x1234
    qr: query            # query | response
    opcode: query        # query | ...
    rcode: no_error      # response 用
    recursion_desired: true
    questions:
      - name: example.com
        type: A          # A|AAAA|CNAME|NS|PTR|MX|TXT|SOA|SRV
        class: IN
    answers:
      - name: example.com
        type: A
        class: IN
        ttl: 300
        data: 93.184.216.34
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `id` | uint16 | 否 | 事务 ID |
| `qr` | string | 否 | `query`/`response` |
| `opcode` | string | 否 | |
| `rcode` | string | 否 | response 用 |
| `authoritative`/`truncated`/`recursion_desired`/`recursion_available`/`authenticated_data`/`checking_disabled` | bool | 否 | 标志位 |
| `questions` | [] | 否 | 查询记录 |
| `answers`/`authorities`/`additionals` | [] | 否 | 资源记录 |

## question 字段

| 字段 | 必填 | 说明 |
|------|------|------|
| `name` | 是 | 域名 |
| `type` | 否 | A/AAAA/CNAME/NS/PTR/MX/TXT/SOA/SRV |
| `class` | 否 | 缺省 IN |

## RR(资源记录)字段

| 字段 | 必填 | 说明 |
|------|------|------|
| `name` | 是 | 域名 |
| `type` | 否 | 同上 |
| `class` | 否 | 缺省 IN |
| `ttl` | 否 | |
| `data` | 与 `payload_hex` 二选一 | 结构化 RDATA(按 type 解析,如 A 的 IP、MX 的 pref+exchange) |
| `payload_hex` | 与 `data` 二选一 | 原始 RDATA 字节(`0x...`),用于畸形/未知 type |

> 校验:至少一个 question 或 RR;`data` 与 `payload_hex` 互斥。
