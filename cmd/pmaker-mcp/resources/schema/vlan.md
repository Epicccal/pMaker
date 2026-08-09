# vlan —— 802.1Q / QinQ(L2)

可重复( QinQ 双层甚至多层 VLAN)。后接 `vlan`(继续套标签)或网络层。

```yaml
- vlan: { vid: 100, tpid: 0x8100, type: 0x0800 }
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `vid` | uint16 | 是 | VLAN ID |
| `tpid` | `Hex` | 否 | **下一层**标签的 TPID(next==vlan 时映射到 Dot1Q.Type);标准内层 `0x8100` |
| `type` | `Hex` | 否 | 显式覆盖 next-proto(制造断链);后接 ipv4 自动 `0x0800` |

## QinQ 示例

```yaml
- eth:  { src: "...", dst: "...", ethertype: 0x88a8 }  # S-TAG TPID
- vlan: { vid: 100, tpid: 0x8100 }                      # 外层 S-TAG,下一层仍是 VLAN
- vlan: { vid: 200 }                                    # 内层 C-TAG,next 自动推导为 IPv4
- ipv4: { ... }
```

> **验证点常在 TPID**:标准 S-TAG 是 `0x88a8`,但很多设备用 `0x8100` 做双层。逐层显式指定即可测"设备认不认非标 TPID"。
