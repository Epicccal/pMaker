# eth —— 以太网层(L2)

栈中最外层(除非走 raw link_type)。后接 `vlan` / `ipv4` / `ipv6` / `gre` / 自定义。

```yaml
- eth: { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb", ethertype: 0x88a8 }
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `src` | MAC 字符串 | 是 | 源 MAC,`aa:bb:cc:dd:ee:ff` 形式 |
| `dst` | MAC 字符串 | 是 | 目的 MAC |
| `ethertype` | `Hex` | 否 | 显式覆盖下一层 EtherType(自动推导时无需写);QinQ 外层 S-TAG 常用 `0x88a8` |

## next-proto 串接

- 后接 `vlan` → 自动 `0x8100`(QinQ 外层可显式 `0x88a8`)
- 后接 `ipv4` → `0x0800`;`ipv6` → `0x86dd`
- 显式设 `ethertype` 即制造**解析断链**(畸形用例)
