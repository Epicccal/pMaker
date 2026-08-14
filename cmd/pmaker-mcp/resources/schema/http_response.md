# http_response —— HTTP 响应(L7,走 tcp)

```yaml
- http_response:
    version: HTTP/1.1
    status: 200
    reason: OK
    headers:
      Server: nginx/1.24.0
      Content-Type: text/html; charset=utf-8
      Content-Length: auto        # auto = 由 body 长度自动计算
    body: |
      <html><body>Hello</body></html>
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `version` | string | 否 | 缺省 HTTP/1.1;非空需符合 `HTTP/x.y` 文法(如 `HTTP/1.0`/`HTTP/2`/`HTTP/3.0`),否则报错并引导 `payload`/`payload_hex` |
| `status` | int | 否 | 状态码;空值(0)走默认 200,非空需在 100-599 |
| `reason` | string | 否 | 状态短语 |
| `headers` | map[string]string | 否 | 头部;`Content-Length: auto` 自动按 body 长度计算;保留声明顺序、支持重复头 |
| `body` | string | 否 | 响应体;可用 `@file(...)` 注入 |

> headers 保留 YAML 声明顺序输出(不再按 key 字典序);支持重复头(如多个 `Set-Cookie`)。

### 校验

- `version` 非空时需符合 `HTTP/x.y` 文法(大小写敏感,`HTTP` 为大写;允许 `HTTP/2` 这类无 minor 写法);非标值报错并引导改用 `payload`/`payload_hex`。
- `status` 空值(0)合法(走 builder 默认 200);非空需在 100-599,越界(如 99/600)报错并引导 `payload`/`payload_hex`。
- `version`/`reason` **可含 CR/LF**:响应拆分是受支持的畸形构造场景,不拦截。需要精确字节的其他畸形另可走 `payload`/`payload_hex`。
