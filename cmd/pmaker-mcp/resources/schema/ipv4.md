# ipv4 —— IPv4 层(L3)

```yaml
- ipv4: { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64, protocol: gre, checksum: 0xdead, total_length: 9999 }
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `src` | IPv4 字符串 | 是 | 源地址 |
| `dst` | IPv4 字符串 | 是 | 目的地址 |
| `ttl` | uint8 | 否 | 缺省由 gopacket 给定 |
| `protocol` | string | 否 | 显式覆盖下一层协议(`tcp`/`udp`/`gre`/`ipv4`);自动推导时无需写 |
| `checksum` | `Hex` | 否 | 两态覆盖:不写=自动计算;写值=关闭自动计算,原样上 wire(构造错误 checksum) |
| `total_length` | `Hex` | 否 | 两态覆盖:不写=自动计算(整包字节数含头);写值=原样上 wire(构造撒谎总长度) |
| `header_length` | `Hex` | 否 | 两态覆盖(IHL,4 位 0-15):不写=自动计算;写值=原样上 wire(注意:0xF 是上限,0x10+ 会在校验阶段被拒) |

## next-proto 串接

- 后接 `tcp` → protocol=6;`udp` → 17;`gre` → 47;`ipv4` → 4(隧道)
- 显式 `protocol` 制造断链;`checksum`/`total_length`/`header_length` 两态覆盖构造错误校验和/撒谎长度
- `total_length` 与 `header_length` 独立覆盖:只写其一时,另一个仍自动计算(不会连带着归零)
