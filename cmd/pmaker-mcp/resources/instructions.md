# pMaker MCP Server 使用说明

pMaker 通过 MCP 离线生成确定性 pcap(同一 YAML 逐字节相同),不发包。

## 标准工作流

1. 不熟悉语法先读 resource `pmaker://schema/_conventions` 与 `pmaker://examples`;
2. 编写场景 YAML,调 `generate_yaml`(仅校验归档)或 `generate_pcap`(校验 + 出包);
3. 硬错在 `errors` 里带字段路径,照改 YAML 重试;软告警在 `warnings` 里
   (`code` + 路径 + 改法),故意构造畸形包时可直接忽略;
4. 成功输出的 `packet_count` 与 `summary`(每包:方向端点 + 层栈 + 时间戳)
   即最终结果,直接交付。

## 禁止事后校验

生成即校验,且输出确定性可复现。不要用 tshark / Wireshark / scapy / Python 等
工具回读生成的 pcap 来"验证"构造正确性——那是重复劳动;`summary` 与预期不符时
优先怀疑 YAML,改后重新生成即可。(仅当用户明确要求解析 pcap 时除外。)