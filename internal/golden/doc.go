// Package golden 是 pMaker 的端到端(e2e)测试包。
//
// 它跑完整链路 scenario.Load → scenario.Validate → plan.Plan →
// builder.BuildPlanned → writer.WriteTo,把 examples/ 下每个 YAML 生成 pcap
// 并与 testdata/<协议>/<name>.pcap 的 golden 逐字节比对。
//
// 本包是 test-only e2e 包,无导出 API。它故意反向依赖 builder/plan/writer
// ——这正是它存在的理由:把端到端验证从最底层包(scenario)中抽出来,
// 避免底层包的测试反向依赖整条上层链路。
//
// 归属判据(加协议时据此决定测试落点):
//
//   - 比对 testdata/*.pcap 或跨 ≥3 个包断言最终 pcap 字节 → 属本 golden 包;
//   - 拿 examples 当输入、只断言本包行为(如 builder 的字节转义、flow 的 seq/ack 推导)
//     → 留在该包自己的单测。
package golden
