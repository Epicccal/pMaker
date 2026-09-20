<p align="center">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.25%2B-00ADD8?style=flat&logo=go&logoColor=white">
  <a href="https://github.com/Epicccal/pMaker/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Epicccal/pMaker/ci.yml?branch=main&label=CI&style=flat"></a>
  <a href="https://goreportcard.com/report/github.com/Epicccal/pMaker"><img alt="Go Report" src="https://goreportcard.com/badge/github.com/Epicccal/pMaker"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-MIT-blue?style=flat"></a>
</p>

<div align="center">
  <a href="https://github.com/Epicccal/pMaker">
    <img src="img/pMaker.png" alt="pMaker" width="120">
  </a>

  <h1 align="center">pMaker</h1>

  <p align="center">
    <strong>Generate Pcap Easier Again</strong>
    <br />
    Build reproducible offline traffic samples with declarative YAML 
    — test traffic as readable, reviewable, and regression-friendly as code.
    <br />
    <a href="examples"><strong>Browse example scenarios »</strong></a>
    <br />
    <br />
    <a href="cmd/pmaker-mcp/resources/schema">Schema reference</a>
    &middot;
    <a href="https://github.com/Epicccal/pMaker/issues/new">Report a bug</a>
    &middot;
    <a href="https://github.com/Epicccal/pMaker/issues/new">Request a feature</a>
    &middot;
    <a href="README.md">中文</a>
  </p>
</div>

## About pMaker

**pMaker is an offline pcap constructor: describe protocol stacks and session behavior in YAML, output deterministic `.pcap` files.**

It turns ad-hoc traffic crafting into test assets that live in your repository.

```console
$ pmaker gen -f examples/http/get.yaml -o out.pcap
Output: out.pcap
Packets:
[ 1] 2020-01-01T00:00:00.000000Z 10.0.0.10:49152 -> 10.0.0.80:80  eth/ipv4/tcp
[ 2] 2020-01-01T00:00:00.001000Z 10.0.0.10:49152 <- 10.0.0.80:80  eth/ipv4/tcp
[ 3] 2020-01-01T00:00:00.002000Z 10.0.0.10:49152 -> 10.0.0.80:80  eth/ipv4/tcp
[ 4] 2020-01-01T00:00:00.003000Z 10.0.0.10:49152 -> 10.0.0.80:80  eth/ipv4/tcp/http
[ 5] 2020-01-01T00:00:00.004000Z 10.0.0.10:49152 <- 10.0.0.80:80  eth/ipv4/tcp
[ 6] 2020-01-01T00:00:00.005000Z 10.0.0.10:49152 <- 10.0.0.80:80  eth/ipv4/tcp/http
...
11 packets generated
```

The input for that command is a complete HTTP GET session scenario:

```yaml
link_type: ethernet
base_time: "2020-01-01T00:00:00Z"
flows:
  - name: http-get-200
    stack:   # src = SYN initiator, dst = SYN receiver
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }   # handshake and teardown auto-expanded
    messages:
      - from: src
        stack:
          - http_request: { method: GET, url: /index.html, headers: { Host: example.com } }
      - from: dst
        stack:
          - http_response: { status: 200, auto_content_length: true, body: "hello" }
```

seq/ack derivation, three-way handshake, four-way teardown, and peer ACKs are all filled in by the flow expander.

### Core Features

| Feature | Description |
|---------|-------------|
| **Declarative YAML** | Describe packets/flows as code — reviewable, diff-able |
| **Arbitrary layer nesting** | QinQ, recursive GRE encapsulation — no fixed L2/L3/L4 slots |
| **Stateful flows** | TCP: auto handshake, seq/ack derivation, MSS segmentation, FIN/RST teardown; UDP: bidirectional datagram sessions |
| **Malformed & evasion** | Per-field `checksum`/`length` overrides, raw byte injection, broken next-proto chains |
| **Deterministic output** | Same scenario → byte-identical pcap |
| **Pure Go** | Static cross-platform binary via `pcapgo` |
| **MCP server** | Expose validation and generation as MCP tools for LLM agents |

### Additional Features

- next-proto and EtherType auto-derivation; per-layer override to craft broken parse chains
- The IP layer supports automatic fragmentation based on the MTU parameter
- TCP/UDP checksum pseudo-header binds to the nearest IP layer; auto-selects inner IP in multi-encap
- Cross-flow `start_after` to anchor timing dependencies between flows and messages
- `base_time` and `offset_time` for deterministic absolute and relative timestamps
- HTTP `Content-Length` auto-fill
- HTTP Content-Encoding: gzip / deflate / deflate_raw / br / zstd / compress
- HTTP Transfer-Encoding: chunked / gzip / deflate / deflate_raw / compress
- ICMP echo/reply and error message derivation
- DNS records: A / AAAA / CNAME / NS / PTR / MX / TXT / SOA / SRV
- RFC 5322 Internet Message Format
- RFC 2045 MIME Content-Transfer-Encoding
- File placeholder `@file(path)`: inject raw bytes from a file relative to workdir

Field-level semantics and design rationale are in [CLAUDE.md](CLAUDE.md).

### Protocol Coverage

Layer names are canonical in `internal/scenario/layer_decode.go`; field reference is in the [schema docs](cmd/pmaker-mcp/resources/schema).

| Layer | Names |
|-------|-------|
| L2 | `eth`, `vlan` |
| L3 | `ipv4`, `ipv6`, `gre`, `vxlan` |
| L4 | `tcp`, `udp`, `tcp_session`, `udp_session` |
| Control | `icmp`, `icmpv6` |
| Application | `dns`, `http_request`, `http_response`, `ftp_request`, `ftp_response`, `telnet`, `smtp_request`, `smtp_response`, `pop3_request`, `pop3_response`, `imap_request`, `imap_response`, `eml_data` |
| Fallback | `payload`, `payload_hex` |

## Quick Start

### Install

- Direct install:

```sh
# Requires Go 1.25+
go install github.com/Epicccal/pMaker/cmd/pmaker@latest
```

- Build from source (includes MCP server):

```sh
git clone https://github.com/Epicccal/pMaker.git && cd pMaker
CGO_ENABLED=0 go build -o bin/pmaker ./cmd/pmaker
CGO_ENABLED=0 go build -o bin/pmaker-mcp ./cmd/pmaker-mcp
```

### CLI

```sh
pmaker gen -f examples/http/get.yaml -o out.pcap          # generate pcap
pmaker validate -f examples/tunnel/qinq_gre.yaml          # validate only, no output
pmaker version                                            # print version
```

### MCP Server

Client config example (Claude Code):

```sh
claude mcp add -s user pmaker -- /path/to/bin/pmaker-mcp -workdir /path/to/scenarios
```

or

```jsonc
// mcp.json
{
  "mcpServers": {
    "pmaker": {
      "command": "/path/to/bin/pmaker-mcp",
      "args": ["-workdir", "/path/to/scenarios"]
    }
  }
}
```

| Tool | Purpose |
|------|---------|
| `generate_yaml` | Validate scenario YAML; persist to `workdir/yaml/` on success |
| `generate_pcap` | Validate YAML and generate pcap to `workdir/pcap/`; archive the YAML alongside |

| Resource | Purpose |
|----------|---------|
| `pmaker://schema` | Syntax overview |
| `pmaker://schema/_conventions` | Global conventions (two-state override / `@file` / hex / fallback / framing) — read once before writing any scenario |
| `pmaker://schema/{layer}` | Per-layer field reference |
| `pmaker://examples` | Example catalog (dynamic scan) |
| `pmaker://examples/{protocol}/{name}` | A single example YAML, verbatim |

## Contributing

PRs welcome. Run `make quality` (gofmt + vet + lint + test) before submitting.

Steps for adding a new protocol (builder / scenario / examples / MCP schema / golden tests) are in the "新增一个协议的步骤" section of [CLAUDE.md](CLAUDE.md). New protocols require both a conformant example and a malformed example, plus a generated golden baseline.

Design constraints, data flow, and flow timing semantics are also in [CLAUDE.md](CLAUDE.md).

## License

Distributed under the MIT License — see [LICENSE](LICENSE). Maintained by [@Epicccal](https://github.com/Epicccal).
