"""引擎级回归测试：去重键、时间桶、DNS 归因、TCP 握手、时间范围摘要。

直接构造 PacketRecord 调用引擎内部求值，验证报告中的 P0/P1 语义修复。
"""
from __future__ import annotations

from app.analysis.engine import AnalysisEngine, run_analysis
from app.analysis.features.sessions import aggregate_flows, build_dns_map
from app.analysis.parsing.base import PacketRecord


def _mk_strategy(sid="test.rule", scope="packet", conditions=None, window=None, **kw):
    strat = {
        "id": sid, "name": sid, "version": "1.0.0", "category": "test",
        "scope": scope, "severity": "medium", "weight": 10, "confidence": 1.0,
        "description": "", "conditions": conditions or {"field": "ip.src", "op": "eq", "value": "1.1.1.1"},
    }
    if window is not None:
        strat["window"] = window
    strat.update(kw)
    return strat


def _tcp(frame, ts, src, dst, sport, dport, flags="S"):
    return PacketRecord(frame_number=frame, timestamp=ts, length=60,
                        src_ip=src, dst_ip=dst, protocol="tcp", transport="tcp",
                        src_port=sport, dst_port=dport,
                        tcp_syn="S" in flags, tcp_ack="A" in flags,
                        tcp_rst="R" in flags, tcp_fin="F" in flags, tcp_push="P" in flags)


def _dns(frame, ts, src, dst, sport, dport, qname, qid, qr, rcode=None):
    return PacketRecord(frame_number=frame, timestamp=ts, length=60,
                        src_ip=src, dst_ip=dst, protocol="dns", transport="udp",
                        src_port=sport, dst_port=dport, dns_query=qname,
                        dns_transaction_id=qid, dns_response=bool(qr), dns_rcode=rcode)


class TestDedup:
    def test_two_packet_hits_not_merged(self):
        """两个分别命中同一包级策略的包必须产生两条告警（回归：原来只留 1 条）。"""
        strat = _mk_strategy(scope="packet", conditions={"field": "ip.src", "op": "eq", "value": "10.0.0.1"})
        records = [
            _tcp(1, 100.0, "10.0.0.1", "10.0.0.2", 1000, 80),
            _tcp(2, 100.5, "10.0.0.1", "10.0.0.2", 1000, 80),
        ]
        eng = AnalysisEngine("unused.pcap", [strat])
        eng._evaluate_strategy(strat, records, {})
        assert len(eng.alerts) == 2, eng.alerts
        assert {a["evidence_packets"][0] for a in eng.alerts} == {1, 2}

    def test_distinct_windows_keep_events(self):
        """同一实体在两个不相邻时间桶命中 → 保留两个事件（回归：跨桶被错误合并）。"""
        strat = _mk_strategy(
            scope="session", window={"seconds": 60, "group_by": ["ip.src"]},
            conditions={"field": "session.syn_count", "op": "gte", "value": 1})
        records = [_tcp(1, 100.0, "1.1.1.1", "2.2.2.2", 1111, 80),
                   _tcp(2, 1000.0, "1.1.1.1", "2.2.2.2", 2222, 443)]
        eng = AnalysisEngine("unused.pcap", [strat])
        eng._evaluate_strategy(strat, records, {})
        assert len(eng.alerts) == 2, eng.alerts
        assert sorted(a["time_start"] for a in eng.alerts) == [100.0, 1000.0]

    def test_multi_window_overlap_picks_strongest(self):
        """多窗口重叠只择强：同一实体同一规范桶内跨窗口合并为 1 条，不同时间点各自保留。"""
        strat = _mk_strategy(
            scope="session", window={"seconds": 60, "multi": [1, 300], "group_by": ["ip.src"]},
            conditions={"field": "session.syn_count", "op": "gte", "value": 1})
        # t=100 处 3 个 SYN；t=5000 处 2 个 SYN
        records = []
        for i in range(3):
            records.append(_tcp(1 + i, 100.0 + i * 0.001, "1.1.1.1", "2.2.2.2", 1111, 80))
        for i in range(2):
            records.append(_tcp(10 + i, 5000.0 + i * 0.001, "1.1.1.1", "2.2.2.2", 1111, 80))
        eng = AnalysisEngine("unused.pcap", [strat])
        eng._evaluate_strategy(strat, records, {})
        assert len(eng.alerts) == 2, eng.alerts
        syn_counts = sorted(a["stats"]["syn_count"] for a in eng.alerts)
        assert syn_counts == [2, 3], syn_counts


class TestDnsAttribution:
    def test_nxdomain_attributed_to_client(self):
        """NXDOMAIN 突增告警必须归因到发起查询的客户端，而不是 DNS 服务器。"""
        strat = _mk_strategy(
            scope="host", window={"seconds": 300, "group_by": ["ip.src"]},
            conditions={"all": [
                {"field": "session.dns_query_count", "op": "gte", "value": 10},
                {"field": "session.dns_nxdomain_ratio", "op": "gte", "value": 0.7},
            ]})
        records = []
        for i in range(10):
            records.append(_dns(i * 2 + 1, 100.0 + i * 0.01, "10.0.0.5", "8.8.8.8",
                                 20000 + i, 53, f"q{i}.evil.com", i, qr=0))
            records.append(_dns(i * 2 + 2, 100.01 + i * 0.01, "8.8.8.8", "10.0.0.5",
                                 53, 20000 + i, f"q{i}.evil.com", i, qr=1, rcode=3))
        eng = AnalysisEngine("unused.pcap", [strat])
        eng.dns_map = build_dns_map(records)
        eng._evaluate_strategy(strat, records, {})
        assert len(eng.alerts) == 1, eng.alerts
        assert eng.alerts[0]["src_ip"] == "10.0.0.5", eng.alerts
        assert eng.alerts[0]["dst_ip"] == "8.8.8.8", eng.alerts
        assert eng.alerts[0]["stats"]["packet_count"] == 10

    def test_dns_query_count_only_queries(self):
        """分组特征里 dns_query_count 只统计查询包（qr=0），响应不计入。"""
        records = [
            _dns(1, 100.0, "10.0.0.5", "8.8.8.8", 20000, 53, "a.example.com", 1, qr=0),
            _dns(2, 100.01, "8.8.8.8", "10.0.0.5", 53, 20000, "a.example.com", 1, qr=1, rcode=0),
        ]
        strat = _mk_strategy(scope="host", window={"seconds": 300, "group_by": ["ip.src"]},
                             conditions={"field": "session.dns_query_count", "op": "gte", "value": 1})
        eng = AnalysisEngine("unused.pcap", [strat])
        eng.dns_map = build_dns_map(records)
        eng._evaluate_strategy(strat, records, {})
        # 只有客户端组命中（query_count=1），服务器组 query_count=0 不命中
        assert len(eng.alerts) == 1
        assert eng.alerts[0]["src_ip"] == "10.0.0.5"


class TestTcpHandshake:
    def test_handshake_incomplete_without_final_ack(self):
        records = [_tcp(1, 100.0, "10.0.0.200", "10.0.0.5", 12345, 80, flags="S"),
                   _tcp(2, 100.01, "10.0.0.5", "10.0.0.200", 80, 12345, flags="SA")]
        flows = aggregate_flows(records)
        f = next(iter(flows.values()))
        assert not f.completed_handshake

    def test_handshake_completed_with_final_ack(self):
        records = [_tcp(1, 100.0, "10.0.0.200", "10.0.0.5", 12345, 80, flags="S"),
                   _tcp(2, 100.01, "10.0.0.5", "10.0.0.200", 80, 12345, flags="SA"),
                   _tcp(3, 100.02, "10.0.0.200", "10.0.0.5", 12345, 80, flags="A")]
        flows = aggregate_flows(records)
        f = next(iter(flows.values()))
        assert f.completed_handshake

    def test_initiator_not_affected_by_ip_sorting(self):
        """发起方是首个 SYN 的发送方，不因端点字符串排序颠倒（10.0.0.200 > 10.0.0.5 也要当 src）。"""
        records = [_tcp(1, 100.0, "10.0.0.200", "10.0.0.5", 12345, 80, flags="S"),
                   _tcp(2, 100.01, "10.0.0.5", "10.0.0.200", 80, 12345, flags="SA"),
                   _tcp(3, 100.02, "10.0.0.200", "10.0.0.5", 12345, 80, flags="A")]
        flows = aggregate_flows(records)
        f = next(iter(flows.values()))
        assert f.src_ip == "10.0.0.200"
        assert f.dst_ip == "10.0.0.5"
        assert f.initiator_ip == "10.0.0.200"

    def test_rst_after_synack_counted_from_initiator(self):
        records = [_tcp(1, 100.0, "10.0.0.200", "10.0.0.5", 12345, 80, flags="S"),
                   _tcp(2, 100.01, "10.0.0.5", "10.0.0.200", 80, 12345, flags="SA"),
                   _tcp(3, 100.02, "10.0.0.200", "10.0.0.5", 12345, 80, flags="R")]
        flows = aggregate_flows(records)
        f = next(iter(flows.values()))
        assert f.rst_after_synack_count == 1


class TestEngineIntegration:
    def test_correlation_scope_not_executed(self, tmp_path):
        from tests.fixtures import gen
        p = tmp_path / "n.pcap"
        gen.make_normal_pcap(str(p))
        strat = _mk_strategy(sid="test.corr", scope="correlation",
                             conditions={"field": "file.packet_count", "op": "gte", "value": 0})
        result = run_analysis(str(p), [strat])
        assert result["alerts"] == []

    def test_time_range_summary_uses_filtered(self, tmp_path):
        """时间范围分析的包数/起止时间/时长必须来自过滤后的数据（回归：曾用全量解析时间戳）。"""
        from tests.fixtures import gen
        p = tmp_path / "s.pcapng"
        gen.make_scan_pcap(str(p), n_ports=20)   # 8 条 DNS + 40 条扫描
        base = 1700000000.0
        result = run_analysis(str(p), [], time_range=[base + 0.5, base + 5.0])
        ps = result["summary"]["parse_stats"]
        assert ps["packets"] == 40            # DNS 包被时间范围排除
        assert ps["first_ts"] == base + 1.0   # 扫描从 base+1 开始
        # 最后一个扫描端口：base+1+19*0.001 的 SYN 与其后 0.0005 的 RST
        assert ps["last_ts"] == base + 1.0 + 19 * 0.001 + 0.0005
        assert ps["duration"] > 0
