"""单元测试：会话聚合与分组特征（文档 12.1/12.2）。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analysis.features.sessions import aggregate_flows, build_groups
from app.analysis.parsing.scapy_parser import parse_file
from tests.fixtures import gen


def _fixture(tmp_path, name, maker, **kw):
    path = tmp_path / name
    maker(str(path), **kw)
    records, stats = parse_file(str(path))
    assert records
    return records


class TestFlowAggregation:
    def test_bidirectional_handshake(self, tmp_path):
        records = _fixture(tmp_path, "t.pcap", gen.make_normal_pcap)
        flows = aggregate_flows(records)
        # HTTP 流：SYN + SYNACK + ACK(+data) → 已完成握手
        http_flows = [f for f in flows.values() if f.protocol == "tcp" and f.http_request_count]
        assert len(http_flows) == 1
        f = http_flows[0]
        assert f.completed_handshake
        assert f.syn_count == 1 and f.synack_count == 1 and f.ack_count >= 1
        assert f.dns_query_count == 0

    def test_dns_flow(self, tmp_path):
        records = _fixture(tmp_path, "t.pcap", gen.make_normal_pcap)
        flows = aggregate_flows(records)
        dns_flows = [f for f in flows.values() if f.dns_query_count]
        assert len(dns_flows) == 1
        # 只统计查询包（qr=0），响应不计入 dns_query_count
        assert dns_flows[0].dns_query_count == 1

    def test_scan_flow_counts(self, tmp_path):
        records = _fixture(tmp_path, "s.pcapng", gen.make_scan_pcap, n_ports=150)
        flows = aggregate_flows(records)
        syn_flows = [f for f in flows.values() if f.syn_count > 0]
        assert len(syn_flows) == 150  # 每端口一个流
        assert all(f.pure_syn_count == 1 for f in syn_flows)
        assert all(f.rst_count == 1 for f in syn_flows)  # 端口关闭 RST
        assert all(not f.completed_handshake for f in syn_flows)


class TestGrouping:
    def test_window_slicing(self, tmp_path):
        records = _fixture(tmp_path, "s.pcapng", gen.make_scan_pcap, n_ports=30)
        groups = build_groups(records, ["ip.src", "ip.dst"], window_seconds=60)
        # 扫描发生在 1 秒内，全部落在一个 60s 窗口
        scan_groups = [g for g in groups if g.key_values.get("ip.src") == "10.0.0.1"]
        assert len(scan_groups) == 1
        vals = scan_groups[0].values("session")
        assert vals["session.syn_count"] == 30
        assert vals["session.distinct_dst_ports"] == 30
        assert vals["session.syn_pure_ratio"] == 1.0
        assert vals["session.handshake_completion_ratio"] == 0.0
        assert vals["session.payload_ratio"] == 0.0

    def test_multi_windows(self, tmp_path):
        records = _fixture(tmp_path, "s.pcapng", gen.make_scan_pcap, n_ports=20)
        groups = build_groups(records, ["ip.src", "ip.dst"], window_seconds=60,
                              multi_windows=[1, 10, 60, 300])
        # 每种窗口一个"扫描源"分组（RST 回包与 DNS 形成其他分组）
        scan_groups = [g for g in groups if g.key_values.get("ip.src") == "10.0.0.1"]
        assert len(scan_groups) == 4

    def test_beacon_periodicity(self, tmp_path):
        records = _fixture(tmp_path, "b.pcap", gen.make_beacon_pcap, n=8, interval=5.0)
        groups = build_groups(records, ["ip.src", "ip.dst", "tcp.dstport"], window_seconds=300)
        # 分组是方向性的：发起方向（dst_port=4444）一组，回包方向一组
        out = next(g for g in groups if g.key_values.get("tcp.dstport") == 4444)
        vals = out.values("session")
        assert vals["session.packet_count"] == 8
        assert vals["session.periodicity_score"] >= 0.9
        assert vals["session.interval_mean_ms"] > 4000

    def test_host_grouping(self, tmp_path):
        records = _fixture(tmp_path, "s.pcapng", gen.make_scan_pcap, n_ports=20)
        groups = build_groups(records, ["ip.src"], window_seconds=None)
        scan = next(g for g in groups if g.key_values.get("ip.src") == "10.0.0.1")
        vals = scan.values("host")
        assert vals["host.ip"] == "10.0.0.1"
        assert vals["host.connections"] == 1
        assert vals["host.distinct_dst_ports"] == 20
        assert vals["host.syn_count"] == 20
