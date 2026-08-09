# telnet —— TELNET 事件(L7,走 tcp)

一个 `telnet` 层 = 一个 TELNET 事件(IAC 命令 / subnegotiation / NVT 文本),序列化为 TCP payload。
多事件:同段内层栈重复多个 `telnet` 层拼接;跨段用 flow `messages`。

```yaml
- telnet:
    command: WILL
    option: ECHO
```

NVT 纯文本(command 留空):

```yaml
- telnet:
    args: "login: "
```

NAWS 二进制 subneg(80×24):

```yaml
- telnet:
    command: SB
    option: NAWS
    args_hex: "0x00500018"
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `command` | string | 否 | WILL/WONT/DO/DONT/SB/GA/BRK/IP/AO/AYT/EC/EL/NOP/DM/EOR;空=纯 NVT 文本(须有 args/args_hex) |
| `option` | string | 否 | option 码(已知名 ECHO/SGA/TTYPE/NAWS/… 或十进制/0x 数字);仅协商/SB 用 |
| `args` | string | 否 | 文本(SB subneg 内容或 NVT 文本);字面 0xFF 自动转义为 IAC IAC;与 `args_hex` 互斥 |
| `args_hex` | `Hex` | 否 | 二进制原始字节(如 NAWS),不转义;与 `args` 互斥 |

## 规则

- 二字节控制命令(GA/BRK/IP/…)禁带 option/args;WILL/WONT/DO/DONT/SB 必带 option。
- `command`/`option` 校验对齐 DNS/FTP 模式:未列入报错并引导 `payload`/`payload_hex`。
- TTYPE subnegotiation:`args` 视作终端名,builder 自动前缀 `IS` 限定符;TTYPE SEND 用 `args_hex: "0x01"`。
