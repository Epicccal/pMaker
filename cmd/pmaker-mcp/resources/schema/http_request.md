# http_request —— HTTP 请求(L7,走 tcp)

```yaml
- http_request:
    method: GET
    url: /index.html
    version: HTTP/1.1
    headers:
      Host: example.com
      User-Agent: pMaker/0.1
      Accept: "*/*"
    body: ""
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `method` | string | 否 | 缺省 GET |
| `url` | string | 否 | 请求路径 |
| `version` | string | 否 | 缺省 HTTP/1.1;非空需符合 `HTTP/x.y` 文法(如 `HTTP/1.0`/`HTTP/2`/`HTTP/3.0`),否则报错并引导 `payload`/`payload_hex` |
| `headers` | map[string]string | 否 | 头部(保留 YAML 声明顺序、支持重复头如多个 `Set-Cookie`) |
| `body` | string | 否 | 请求体;可用 `@file(...)` 注入文件内容 |

> headers 保留 YAML 声明顺序输出(不再按 key 字典序);支持重复头(如多个 `Set-Cookie`)。

### 校验

- `version` 非空时需符合 `HTTP/x.y` 文法(大小写敏感,`HTTP` 为大写;允许 `HTTP/2` 这类无 minor 写法);非标值(如 `1.1`、`http/1.1`、`HTTP/x.y`)报错并引导改用 `payload`/`payload_hex`。
- `method`/`url`/`version` **可含 CR/LF**:CRLF 注入(请求走私)是受支持的畸形构造场景,不拦截。需要精确字节的其他畸形(非标 version、私有方法名等)另可走 `payload`/`payload_hex`。
- `method`/`url` 空值合法(走 builder 默认 GET / `/`),不报错。
