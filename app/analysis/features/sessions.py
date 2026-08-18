"""会话（五元组）聚合与分组特征值计算（文档 8.2 步骤 4~6）。

- FlowState：双向五元组流聚合（TCP 握手状态机、DNS/HTTP/TLS 计数、时间间隔）。
  方向状态独立于排序后的端点：首个 SYN（SYN=1, ACK=0）的发送方为发起方；
  握手必须经过 SYN -> 对向 SYN-ACK -> 发起方 ACK 才算完成。
- DNS 事务配对（DnsMap）：查询/响应按（客户端、服务器、事务 ID）关联，
  使 NXDOMAIN 比率按"查询方已匹配到的响应"计算，避免把 DNS 服务器误判为查询发起方。
- 分组：按策略 window.group_by 对包分组（按时间窗口切片），计算 session.* / host.* / file.*
  扁平字段字典，供条件树求值。
"""
from __future__ import annotations

import math
from collections import OrderedDict
from typing import Any, Optional

from app.analysis.operators import shannon_entropy


class FlowState:
    """双向流聚合状态。"""

    __slots__ = (
        "key", "endpoints", "protocol", "src_ip", "dst_ip", "src_port", "dst_port",
        "initiator_ip", "initiator_port", "responder_ip", "responder_port",
        "packet_count", "byte_count", "payload_bytes", "first_ts", "last_ts",
        "syn_count", "pure_syn_count", "synack_count", "ack_count", "rst_count",
        "fin_count", "other_count", "completed_handshake", "rst_after_synack_count",
        "dns_query_count", "http_request_count", "tls_handshake_count",
        "frames", "timestamps", "saw_synack", "handshake_state",
    )

    def __init__(self, key: tuple, endpoints: tuple, protocol: str):
        self.key = key
        self.endpoints = endpoints          # ((ip, port), (ip, port)) 规范化端点（可排序，不决定方向）
        self.protocol = protocol
        # 展示方向（会话表）：一旦确定发起方即被覆盖；未确定前为规范化端点顺序
        self.src_ip, self.dst_ip = endpoints[0][0], endpoints[1][0]
        self.src_port, self.dst_port = endpoints[0][1], endpoints[1][1]
        # 方向状态：首个 SYN 发送方为发起方
        self.initiator_ip: Optional[str] = None
        self.initiator_port: Optional[int] = None
        self.responder_ip: Optional[str] = None
        self.responder_port: Optional[int] = None
        self.packet_count = 0
        self.byte_count = 0
        self.payload_bytes = 0
        self.first_ts = 0.0
        self.last_ts = 0.0
        self.syn_count = 0
        self.pure_syn_count = 0
        self.synack_count = 0
        self.ack_count = 0
        self.rst_count = 0
        self.fin_count = 0
        self.other_count = 0
        self.completed_handshake = False
        self.rst_after_synack_count = 0
        self.dns_query_count = 0
        self.http_request_count = 0
        self.tls_handshake_count = 0
        self.frames: list[int] = []
        self.timestamps: list[float] = []
        self.saw_synack = False
        self.handshake_state = "idle"  # idle -> syn_sent -> synack_seen -> completed

    # ------------------------------------------------------------ 方向状态机
    def _set_direction(self, src_ip, src_port, dst_ip, dst_port, from_synack: bool) -> None:
        """首个 TCP 握手包决定方向：SYN 发送方为发起方；SYN-ACK 则推断发起方在对侧。"""
        if self.initiator_ip is not None:
            return
        if from_synack:
            self.responder_ip, self.responder_port = src_ip, src_port
            self.initiator_ip, self.initiator_port = dst_ip, dst_port
        else:
            self.initiator_ip, self.initiator_port = src_ip, src_port
            self.responder_ip, self.responder_port = dst_ip, dst_port
        self.src_ip, self.dst_ip = self.initiator_ip, self.responder_ip
        self.src_port, self.dst_port = self.initiator_port, self.responder_port

    def _from_initiator(self, rec) -> bool:
        return (self.initiator_ip is not None
                and rec.src_ip == self.initiator_ip
                and rec.src_port == self.initiator_port)

    # ------------------------------------------------------------ 收包
    def add(self, rec) -> None:
        """收包（双向流内）。"""
        self.packet_count += 1
        self.byte_count += rec.length
        self.payload_bytes += rec.payload_length
        ts = rec.timestamp
        if not self.first_ts or ts < self.first_ts:
            self.first_ts = ts
        if ts > self.last_ts:
            self.last_ts = ts
        if len(self.frames) < 200:
            self.frames.append(rec.frame_number)
        if len(self.timestamps) < 3000:
            self.timestamps.append(ts)

        if rec.transport == "tcp":
            if rec.tcp_syn and rec.tcp_ack:
                self._set_direction(rec.src_ip, rec.src_port, rec.dst_ip, rec.dst_port,
                                    from_synack=True)
                self.synack_count += 1
                self.saw_synack = True
                if self.handshake_state == "syn_sent":
                    self.handshake_state = "synack_seen"
            elif rec.tcp_syn:
                self._set_direction(rec.src_ip, rec.src_port, rec.dst_ip, rec.dst_port,
                                    from_synack=False)
                self.syn_count += 1
                if rec.payload_length == 0:
                    self.pure_syn_count += 1
                if self.handshake_state == "idle":
                    self.handshake_state = "syn_sent"
                self.other_count += 1 if not rec.tcp_fin else 0
            elif rec.tcp_rst:
                self.rst_count += 1
                if self.saw_synack and self._from_initiator(rec):
                    self.rst_after_synack_count += 1
            elif rec.tcp_ack:
                self.ack_count += 1
                if self.handshake_state == "synack_seen" and self._from_initiator(rec):
                    self.handshake_state = "completed"
            elif rec.tcp_fin:
                self.fin_count += 1
            else:
                self.other_count += 1
        else:
            self.other_count += 1

        if rec.protocol == "dns" and rec.dns_response is False:
            self.dns_query_count += 1
        elif rec.protocol == "http":
            self.http_request_count += 1
        elif rec.protocol == "tls":
            self.tls_handshake_count += 1

    def finish(self) -> None:
        self.completed_handshake = self.handshake_state == "completed"
        self.frames.sort()
        self.timestamps.sort()


def flow_key(rec) -> tuple:
    """双向五元组键（基于传输层协议）。"""
    if rec.transport in ("tcp", "udp"):
        a = (rec.src_ip or "", rec.src_port)
        b = (rec.dst_ip or "", rec.dst_port)
        return (tuple(sorted([a, b])), rec.transport)
    return (tuple(sorted([rec.src_ip or "", rec.dst_ip or ""])), rec.transport or rec.protocol)


def aggregate_flows(records: list) -> dict[tuple, FlowState]:
    flows: dict[tuple, FlowState] = {}
    for rec in records:
        key = flow_key(rec)
        state = flows.get(key)
        if state is None:
            endpoints = tuple(sorted([(rec.src_ip or "", rec.src_port),
                                      (rec.dst_ip or "", rec.dst_port)]))
            state = FlowState(key, endpoints, rec.transport or rec.protocol)
            flows[key] = state
        state.add(rec)
    for state in flows.values():
        state.finish()
    return flows


# ---------------------------------------------------------------------------
# DNS 事务配对（查询 → 响应 rcode）
# ---------------------------------------------------------------------------

class DnsMap:
    """按（客户端、服务器、事务 ID）把 DNS 响应关联回其查询，供 NXDOMAIN 归因。"""

    __slots__ = ("_responses",)

    def __init__(self, records: list):
        responses: dict[tuple, list] = {}
        for rec in records:
            if rec.protocol != "dns" or not rec.dns_query or not rec.dns_response:
                continue
            key = (rec.dst_ip, rec.src_ip, rec.dns_transaction_id)
            responses.setdefault(key, []).append(rec)
        self._responses = responses

    def matched_rcode(self, rec) -> Optional[int]:
        """查询包对应的响应 rcode；未匹配到响应返回 None。响应包直接返回自身 rcode。"""
        if rec.dns_response:
            return rec.dns_rcode
        if not rec.dns_query:
            return None
        key = (rec.src_ip, rec.dst_ip, rec.dns_transaction_id)
        resps = self._responses.get(key)
        if not resps:
            return None
        return min(resps, key=lambda r: r.timestamp).dns_rcode


def build_dns_map(records: list) -> DnsMap:
    return DnsMap(records)


# ---------------------------------------------------------------------------
# 分组与字段字典
# ---------------------------------------------------------------------------

def _interval_stats(ts_list: list[float]) -> tuple[float, float]:
    if len(ts_list) < 2:
        return 0.0, 0.0
    ts = sorted(float(t) for t in ts_list)
    deltas = [b - a for a, b in zip(ts, ts[1:]) if b > a]
    if not deltas:
        return 0.0, 0.0
    mean = sum(deltas) / len(deltas)
    if len(deltas) == 1:
        return mean * 1000, 0.0
    var = sum((d - mean) ** 2 for d in deltas) / (len(deltas) - 1)
    return float(mean * 1000), float(math.sqrt(var) * 1000)


class PacketGroup:
    """一次窗口切片 + 分组键下的包集合。"""

    def __init__(self, key_values: dict[str, Any]):
        self.key_values = key_values
        self.packets: list = []
        self.flows: dict[tuple, FlowState] = {}
        self._flow_of: dict[int, FlowState] = {}  # frame -> flow
        self.dns_map: Optional[DnsMap] = None
        self.bucket_key: Optional[str] = None      # 时间桶标识（窗口策略），None = 不切片

    def add(self, rec, flow: FlowState) -> None:
        self.packets.append(rec)
        self._flow_of[rec.frame_number] = flow

    @property
    def frame_numbers(self) -> list[int]:
        return sorted(r.frame_number for r in self.packets)

    # ------------------------------------------------------------------
    def _dns_counts(self) -> tuple[list, int, int]:
        """(查询包列表, 已匹配 NXDOMAIN 数, 已匹配响应数)。"""
        queries = [p for p in self.packets
                   if p.protocol == "dns" and p.dns_response is False and p.dns_query]
        if not queries or self.dns_map is None:
            return queries, 0, 0
        matched = [self.dns_map.matched_rcode(q) for q in queries]
        nxdomain = sum(1 for rc in matched if rc == 3)
        responses = sum(1 for rc in matched if rc is not None)
        return queries, nxdomain, responses

    def values(self, scope: str) -> dict[str, Any]:
        """计算组聚合字段字典（扁平，缺字段省略）。"""
        v: dict[str, Any] = {}
        flows = list(self.flows.values())
        pkts = self.packets
        n = len(pkts)
        total_bytes = sum(p.length for p in pkts)
        payload_bytes = sum(p.payload_length for p in pkts)
        syn = [p for p in pkts if p.tcp_syn and not p.tcp_ack]
        syn_only = [p for p in syn if p.payload_length == 0]
        synack = [p for p in pkts if p.tcp_syn and p.tcp_ack]
        rst = [p for p in pkts if p.tcp_rst]
        ack = [p for p in pkts if p.tcp_ack and not p.tcp_syn and not p.tcp_rst]
        fin = [p for p in pkts if p.tcp_fin]
        first_ts = min(p.timestamp for p in pkts) if pkts else 0.0
        last_ts = max(p.timestamp for p in pkts) if pkts else 0.0
        duration = max(0.0, last_ts - first_ts)

        dns_queries, dns_nxdomain, dns_responses = self._dns_counts()
        http_reqs = [p for p in pkts if p.protocol == "http" and p.http_method]
        tls_hs = [p for p in pkts if p.protocol == "tls" and p.tls_handshake_type]

        # --- session.* ---
        v["session.count"] = len(flows)
        v["session.packet_count"] = n
        v["session.byte_count"] = total_bytes
        v["session.payload_bytes"] = payload_bytes
        v["session.payload_ratio"] = round(payload_bytes / total_bytes, 4) if total_bytes else 0.0
        v["session.first_ts"] = first_ts
        v["session.last_ts"] = last_ts
        v["session.duration"] = round(duration, 4)
        v["session.packet_rate"] = round(n / duration, 4) if duration > 0 else 0.0
        v["session.avg_packet_size"] = round(total_bytes / n, 2) if n else 0.0
        v["session.syn_count"] = len(syn)
        v["session.syn_only_count"] = len(syn_only)
        v["session.syn_pure_ratio"] = round(len(syn_only) / len(syn), 4) if syn else 0.0
        v["session.synack_count"] = len(synack)
        v["session.ack_count"] = len(ack)
        v["session.rst_count"] = len(rst)
        v["session.fin_count"] = len(fin)
        v["session.completed_handshake_count"] = sum(1 for f in flows if f.completed_handshake)
        v["session.handshake_completion_ratio"] = (
            round(sum(1 for f in flows if f.completed_handshake) / max(len(syn), 1), 4))
        v["session.rst_after_synack_count"] = sum(f.rst_after_synack_count for f in flows)
        v["session.failed_connections"] = sum(
            1 for f in flows if f.syn_count > 0 and not f.completed_handshake and f.rst_count == 0)
        v["session.distinct_dst_ports"] = len({p.dst_port for p in pkts if p.dst_port is not None})
        v["session.distinct_src_ports"] = len({p.src_port for p in pkts if p.src_port is not None})
        v["session.distinct_dst_ips"] = len({p.dst_ip for p in pkts if p.dst_ip})
        v["session.distinct_src_ips"] = len({p.src_ip for p in pkts if p.src_ip})
        v["session.dns_query_count"] = len(dns_queries)
        v["session.dns_unique_queries"] = len({p.dns_query for p in dns_queries})
        if dns_queries:
            v["session.dns_longest_query"] = max(len(p.dns_query) for p in dns_queries)
            best = max(dns_queries, key=lambda p: shannon_entropy(p.dns_query))
            v["session.dns_entropy_max"] = round(shannon_entropy(best.dns_query), 4)
            v["dns.query"] = best.dns_query
            v["dns.query_length"] = len(best.dns_query)
        v["dns.base_domain"] = self.key_values.get("dns.base_domain")
        v["session.dns_nxdomain_count"] = dns_nxdomain
        v["session.dns_nxdomain_ratio"] = (
            round(dns_nxdomain / dns_responses, 4) if dns_responses else 0.0)
        v["session.http_request_count"] = len(http_reqs)
        v["session.tls_handshake_count"] = len(tls_hs)
        v["session.tls_client_hello_count"] = len([p for p in tls_hs if p.tls_handshake_type == "client_hello"])

        # 周期特征（Beacon）：会话起始间隔或包到达间隔中更"规律"者
        flow_starts = sorted(f.first_ts for f in self.flows.values() if f.first_ts)
        pkt_ts = sorted(p.timestamp for p in pkts)
        cands: list[tuple[float, float]] = []
        if len(flow_starts) >= 2:
            cands.append(_interval_stats(flow_starts))
        if len(pkt_ts) >= 4:
            cands.append(_interval_stats(pkt_ts))
        if cands:
            best = min(cands, key=lambda x: (x[1] / x[0]) if x[0] > 0 else 1.0)
            mean_ms, std_ms = best
        else:
            mean_ms = std_ms = 0.0
        v["session.interval_mean_ms"] = round(mean_ms, 2)
        v["session.interval_stddev_ms"] = round(std_ms, 2)
        v["session.periodicity_score"] = round(max(0.0, 1 - (std_ms / mean_ms if mean_ms > 0 else 0)), 4)

        # --- 代表包字段 ---
        v["ip.src"] = self.key_values.get("ip.src") or (pkts[0].src_ip if pkts else None)
        v["ip.dst"] = self.key_values.get("ip.dst") or (pkts[0].dst_ip if pkts else None)
        if pkts:
            v["protocol"] = pkts[0].protocol
            v["tcp.dstport"] = pkts[0].dst_port
            v["tcp.srcport"] = pkts[0].src_port
            v["tls.sni"] = next((p.tls_sni for p in pkts if p.tls_sni), None)
            v["http.host"] = next((p.http_host for p in pkts if p.http_host), None)
            v["http.uri"] = next((p.http_uri for p in pkts if p.http_uri), None)
            v["http.method"] = next((p.http_method for p in pkts if p.http_method), None)

        # --- host.* 别名（主机行为） ---
        src_ips = {p.src_ip for p in pkts if p.src_ip}
        dst_ips = {p.dst_ip for p in pkts if p.dst_ip}
        host_ip = self.key_values.get("ip.src") or (next(iter(src_ips), None))
        v["host.ip"] = host_ip
        v["host.packet_count"] = n
        v["host.bytes"] = total_bytes
        v["host.connections"] = len({p.dst_ip for p in pkts if p.dst_ip})
        v["host.distinct_dst_ports"] = len({p.dst_port for p in pkts if p.dst_port is not None})
        v["host.distinct_dst_ips"] = len(dst_ips)
        v["host.syn_count"] = len(syn)
        v["host.failed_connections"] = sum(
            1 for f in flows if f.syn_count > 0 and not f.completed_handshake and f.rst_count == 0)
        v["host.failed_ratio"] = round(v["host.failed_connections"] / max(len(flows), 1), 4)
        v["host.dns_query_count"] = len(dns_queries)
        v["host.nxdomain_ratio"] = v["session.dns_nxdomain_ratio"]
        v["host.http_request_count"] = len(http_reqs)
        v["host.tls_handshake_count"] = len(tls_hs)
        v["host.payload_ratio"] = v["session.payload_ratio"]
        v["host.duration"] = round(duration, 4)
        v["host.packet_rate"] = v["session.packet_rate"]
        v["host.avg_packet_size"] = v["session.avg_packet_size"]

        # --- file.* 别名（文件级） ---
        v["file.packet_count"] = n
        v["file.byte_count"] = total_bytes
        v["file.duration"] = round(duration, 4)
        v["file.unique_ips"] = len(src_ips | dst_ips)
        v["file.unique_domains"] = len({p.dns_base_domain for p in pkts if p.dns_base_domain})
        v["file.syn_count"] = len(syn)
        v["file.dns_query_count"] = len(dns_queries)
        v["file.http_request_count"] = len(http_reqs)
        v["file.tls_handshake_count"] = len(tls_hs)
        v["file.encrypted_ratio"] = round(len([p for p in pkts if p.protocol == "tls"]) / n, 4) if n else 0.0
        v["file.payload_ratio"] = v["session.payload_ratio"]
        v["file.avg_packet_size"] = v["session.avg_packet_size"]

        return v

    def stats(self) -> dict:
        """告警证据统计（文档 6.2.1 建议保存的证据）。"""
        pkts = self.packets
        syn = [p for p in pkts if p.tcp_syn and not p.tcp_ack]
        synack = [p for p in pkts if p.tcp_syn and p.tcp_ack]
        rst = [p for p in pkts if p.tcp_rst]
        frames = self.frame_numbers
        dst_ports = sorted({p.dst_port for p in pkts if p.dst_port is not None})
        no_resp = sum(1 for f in self.flows.values()
                      if f.syn_count > 0 and not f.completed_handshake and f.rst_count == 0)
        return {
            "syn_count": len(syn),
            "syn_only_count": len([p for p in syn if p.payload_length == 0]),
            "synack_count": len(synack),
            "rst_count": len(rst),
            "no_response": no_resp,
            "distinct_dst_ports": len(dst_ports),
            "distinct_dst_ips": len({p.dst_ip for p in pkts if p.dst_ip}),
            "distinct_src_ips": len({p.src_ip for p in pkts if p.src_ip}),
            "packet_count": len(pkts),
            "byte_count": sum(p.length for p in pkts),
            "duration": round(max(0.0, (pkts[-1].timestamp - pkts[0].timestamp) if pkts else 0.0), 3),
            "pure_syn_ratio": round(len([p for p in syn if p.payload_length == 0]) / len(syn), 4) if syn else 0.0,
            "handshake_completion_ratio": round(
                sum(1 for f in self.flows.values() if f.completed_handshake) / max(len(syn), 1), 4),
            "port_samples": dst_ports[:20],
            "first_frame": frames[0] if frames else None,
            "last_frame": frames[-1] if frames else None,
        }


def build_groups(records: list, group_by: list[str], window_seconds: Optional[float],
                 multi_windows: Optional[list[float]] = None,
                 dns_map: Optional[DnsMap] = None,
                 min_window: Optional[float] = None) -> list[PacketGroup]:
    """按 group_by 字段（可选时间窗口切片）构建分组。

    multi_windows 存在时：对每个窗口大小各建一组并返回全部（供策略选择最优窗口）。
    min_window 为 multi 场景中的最小窗口，用于统一时间桶标识，保证同实体跨窗口重叠可去重。
    """
    if multi_windows:
        groups: list[PacketGroup] = []
        min_w = min(multi_windows)
        for w in multi_windows:
            groups.extend(build_groups(records, group_by, w, None,
                                       dns_map=dns_map, min_window=min_w))
        return groups

    key_funcs = [_group_key_fn(f) for f in group_by] if group_by else []

    buckets: OrderedDict[tuple, list] = OrderedDict()
    order: dict[tuple, int] = {}
    for rec in records:
        if window_seconds:
            bucket_idx = int(rec.timestamp // window_seconds)
        else:
            bucket_idx = None
        key_parts = []
        for fn in key_funcs:
            key_parts.append(fn(rec))
        key = tuple(key_parts + [bucket_idx])
        buckets.setdefault(key, []).append(rec)
        order.setdefault(key, len(order))

    result: list[PacketGroup] = []
    for key, pkts in buckets.items():
        kv: dict[str, Any] = {}
        for f, fn in zip(group_by, key_funcs):
            kv[f] = fn(pkts[0])
        group = PacketGroup(kv)
        group.dns_map = dns_map
        if window_seconds:
            w = min_window or window_seconds
            first_pkt_ts = pkts[0].timestamp if pkts else 0.0
            group.bucket_key = f"w{int(first_pkt_ts // w) * w:.0f}"
        flows: dict[tuple, FlowState] = {}
        for rec in pkts:
            fkey = flow_key(rec)
            state = flows.get(fkey)
            if state is None:
                endpoints = tuple(sorted([(rec.src_ip or "", rec.src_port),
                                          (rec.dst_ip or "", rec.dst_port)]))
                state = FlowState(fkey, endpoints, rec.transport or rec.protocol)
                flows[fkey] = state
            state.add(rec)
            group.add(rec, state)
        for state in flows.values():
            state.finish()
        group.flows = flows
        result.append(group)
    return result


def _group_key_fn(field: str):
    """分组字段 → 从 PacketRecord 取值函数。"""
    if field == "session.key":
        return lambda r: flow_key(r)
    if field == "ip.src":
        return lambda r: r.src_ip
    if field == "ip.dst":
        return lambda r: r.dst_ip
    if field in ("src_ip", "dst_ip"):
        return lambda r: getattr(r, field)
    if field == "tcp.srcport":
        return lambda r: r.src_port
    if field == "tcp.dstport":
        return lambda r: r.dst_port
    if field == "udp.srcport":
        return lambda r: r.src_port
    if field == "udp.dstport":
        return lambda r: r.dst_port
    if field == "dns.base_domain":
        return lambda r: r.dns_base_domain
    if field == "http.host":
        return lambda r: r.http_host
    if field == "tls.sni":
        return lambda r: r.tls_sni
    raise ValueError(f"不支持的分组字段: {field}")
