"""分析流水线引擎（文档 8.2）。

parse → 会话聚合 → 分组特征 → 策略匹配 → 证据 → 评分 → 汇总。
单包异常只记 warning；单策略异常不影响任务；支持进度回调与取消。

去重契约：包级告警以 frame 为去重键（每个命中包一条）；窗口级告警以
"策略 + 规范化分组键 + 时间桶标识"为去重键，跨时间桶不合并，多窗口重叠才择强。
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Callable, Optional

from app.analysis.features.sessions import aggregate_flows, build_dns_map, build_groups
from app.analysis.operators import evaluate_condition_tree
from app.analysis.parsing.base import PacketRecord
from app.analysis.parsing.scapy_parser import parse_file
from app.analysis.scoring import context_multiplier, hit_score, normalize, severity_counts
from app.core.errors import ValidationError
from app.core.logging import get_logger

log = get_logger("baize.engine")

MAX_ALERTS_PER_STRATEGY = 500
EVIDENCE_FRAMES = 10
_CANCEL_CHECK_EVERY = 2000


class TaskCancelled(Exception):
    pass


# ---------------------------------------------------------------------------
# 包级字段字典（文档 8.3 统一字段）
# ---------------------------------------------------------------------------

def packet_values(rec: PacketRecord) -> dict[str, Any]:
    v: dict[str, Any] = {
        "frame.number": rec.frame_number,
        "frame.time": rec.timestamp,
        "frame.length": rec.length,
        "protocol": rec.protocol,
        "ip.src": rec.src_ip,
        "ip.dst": rec.dst_ip,
        "ip.proto": rec.ip_proto,
        "eth.src": rec.src_mac,
        "eth.dst": rec.dst_mac,
    }
    if rec.src_port is not None:
        v["tcp.srcport" if rec.protocol in ("tcp", "http", "tls") else "udp.srcport"] = rec.src_port
        v["tcp.dstport" if rec.protocol in ("tcp", "http", "tls") else "udp.dstport"] = rec.dst_port
    if rec.protocol in ("tcp", "http", "tls"):
        v["tcp.flags"] = rec.tcp_flags
        v["tcp.flags.syn"] = rec.tcp_syn
        v["tcp.flags.ack"] = rec.tcp_ack
        v["tcp.flags.rst"] = rec.tcp_rst
        v["tcp.flags.fin"] = rec.tcp_fin
        v["tcp.flags.push"] = rec.tcp_push
        v["tcp.len"] = rec.payload_length
        v["tcp.payload_length"] = rec.payload_length
        v["tcp.payload_head"] = rec.tcp_payload_head
    elif rec.protocol == "udp":
        v["udp.payload_length"] = rec.payload_length
    if rec.dns_query:
        v["dns.query"] = rec.dns_query
        v["dns.qtype"] = rec.dns_qtype
        v["dns.qname_length"] = len(rec.dns_query)
        v["dns.base_domain"] = rec.dns_base_domain
        v["dns.rcode"] = rec.dns_rcode
        v["dns.response"] = rec.dns_response
        v["dns.answers"] = rec.dns_answers
    if rec.http_method:
        v["http.method"] = rec.http_method
        v["http.uri"] = rec.http_uri
        v["http.host"] = rec.http_host
        v["http.user_agent"] = rec.http_user_agent
        v["http.response"] = rec.http_response
        v["http.body_head"] = rec.http_body_head
    if rec.http_status is not None:
        v["http.status_code"] = rec.http_status
        v["http.response"] = True
    if rec.tls_version:
        v["tls.version"] = rec.tls_version
        v["tls.sni"] = rec.tls_sni
        v["tls.handshake_type"] = rec.tls_handshake_type
    if rec.icmp_type is not None:
        v["icmp.type"] = rec.icmp_type
    return v


# ---------------------------------------------------------------------------
# 结果结构
# ---------------------------------------------------------------------------

def _key_to_str(key: tuple) -> str:
    """流键 → 可读字符串（用于会话表主键展示）。"""
    eps, proto = key
    if eps and isinstance(eps[0], tuple):
        return "|".join([f"{ip}:{p}" for ip, p in eps] + [proto])
    return "|".join([str(e) for e in eps] + [proto])


def _session_row(state) -> dict:
    return {
        "session_key": _key_to_str(state.key),
        "src_ip": state.src_ip,
        "dst_ip": state.dst_ip,
        "src_port": state.src_port,
        "dst_port": state.dst_port,
        "protocol": state.protocol,
        "packet_count": state.packet_count,
        "byte_count": state.byte_count,
        "payload_bytes": state.payload_bytes,
        "first_ts": state.first_ts,
        "last_ts": state.last_ts,
        "duration": round(max(0.0, state.last_ts - state.first_ts), 4),
        "syn_count": state.syn_count,
        "pure_syn_count": state.pure_syn_count,
        "synack_count": state.synack_count,
        "ack_count": state.ack_count,
        "rst_count": state.rst_count,
        "fin_count": state.fin_count,
        "other_count": state.other_count,
        "completed_handshake": state.completed_handshake,
        "rst_after_synack_count": state.rst_after_synack_count,
        "dns_query_count": state.dns_query_count,
        "http_request_count": state.http_request_count,
        "tls_handshake_count": state.tls_handshake_count,
        "payload_ratio": round(state.payload_bytes / state.byte_count, 4) if state.byte_count else 0.0,
        "avg_packet_size": round(state.byte_count / state.packet_count, 2) if state.packet_count else 0.0,
    }


def _packet_row(rec: PacketRecord) -> dict:
    return {
        "frame_number": rec.frame_number,
        "timestamp": rec.timestamp,
        "src_mac": rec.src_mac,
        "dst_mac": rec.dst_mac,
        "src_ip": rec.src_ip,
        "dst_ip": rec.dst_ip,
        "protocol": rec.protocol,
        "ip_proto": rec.ip_proto,
        "src_port": rec.src_port,
        "dst_port": rec.dst_port,
        "length": rec.length,
        "payload_length": rec.payload_length,
        "tcp_flags": rec.tcp_flags,
        "tcp_syn": rec.tcp_syn,
        "tcp_ack": rec.tcp_ack,
        "tcp_rst": rec.tcp_rst,
        "tcp_fin": rec.tcp_fin,
        "tcp_push": rec.tcp_push,
        "dns_query": rec.dns_query,
        "dns_qtype": rec.dns_qtype,
        "dns_response": rec.dns_response,
        "dns_rcode": rec.dns_rcode,
        "dns_answers": rec.dns_answers,
        "http_method": rec.http_method,
        "http_uri": rec.http_uri,
        "http_host": rec.http_host,
        "http_user_agent": rec.http_user_agent,
        "http_status": rec.http_status,
        "http_response": rec.http_response,
        "http_body_head": rec.http_body_head,
        "tcp_payload_head": rec.tcp_payload_head,
        "tls_version": rec.tls_version,
        "tls_sni": rec.tls_sni,
        "tls_handshake_type": rec.tls_handshake_type,
        "icmp_type": rec.icmp_type,
        "parse_warnings": rec.parse_warnings,
    }


# ---------------------------------------------------------------------------
# 引擎
# ---------------------------------------------------------------------------

class AnalysisEngine:
    def __init__(self, file_path: str, strategies: list[dict],
                 progress_cb: Optional[Callable[[int, str], None]] = None,
                 cancel_check: Optional[Callable[[], bool]] = None,
                 time_range: Optional[list[float]] = None,
                 severity_threshold: Optional[str] = None):
        self.file_path = file_path
        # 启停属于策略元数据，由任务创建时一次性确定快照；引擎无条件执行传入的每条策略
        self.strategies = list(strategies)
        self.progress_cb = progress_cb or (lambda p, s: None)
        self.cancel_check = cancel_check or (lambda: False)
        self.time_range = time_range
        self.severity_threshold = severity_threshold
        self.records: list[PacketRecord] = []
        self.parse_stats: dict = {}
        self.protocol_stats: dict = {}
        self.alerts: list[dict] = []
        self.dns_map = None
        self._groups_cache: dict[tuple, list] = {}

    def _check_cancel(self) -> None:
        if self.cancel_check():
            raise TaskCancelled("任务已被取消")

    def run(self) -> dict:
        self._check_cancel()
        # 1. 解析
        self.progress_cb(5, "解析流量文件")
        records, stats = parse_file(self.file_path, progress_cb=self._parse_progress)
        self._check_cancel()
        if stats.error:
            raise ValidationError(f"流量文件解析失败: {stats.error}")
        if not records:
            raise ValidationError("文件中没有可解析的数据包")
        if self.time_range:
            start, end = self.time_range[0], self.time_range[1]
            records = [r for r in records if start <= r.timestamp <= end]
            if not records:
                raise ValidationError("时间范围内没有数据包")
        self.records = records
        self.protocol_stats = dict(Counter(r.protocol for r in records))
        # 摘要必须来自过滤后的记录（时间范围分析时不能复用全量解析时间戳）
        first_ts = min((r.timestamp for r in records), default=None)
        last_ts = max((r.timestamp for r in records), default=None)
        self.parse_stats = {
            "packets": len(records),
            "warnings": stats.warnings,
            "first_ts": first_ts,
            "last_ts": last_ts,
            "duration": round((last_ts or 0) - (first_ts or 0), 3),
            "link_type": stats.link_type,
        }

        # 2. 会话聚合
        self.progress_cb(45, "会话聚合")
        flows = aggregate_flows(records)
        session_rows = [_session_row(f) for f in flows.values()]
        session_rows.sort(key=lambda r: r["byte_count"], reverse=True)
        self.parse_stats["sessions"] = len(session_rows)

        # DNS 查询/响应事务表，供 NXDOMAIN 等策略归因
        self.dns_map = build_dns_map(records)

        # 3. 策略匹配
        self.progress_cb(50, "运行识别策略")
        for i, strat in enumerate(self.strategies):
            self._check_cancel()
            self.progress_cb(50 + int(45 * i / max(len(self.strategies), 1)),
                             f"策略: {strat.get('name', strat.get('id', ''))}")
            try:
                self._evaluate_strategy(strat, records, flows)
            except TaskCancelled:
                raise
            except Exception as exc:  # noqa: BLE001  单策略异常不中断任务（验收标准）
                log.warning("strategy evaluation failed", extra={
                    "extra_fields": {"strategy": strat.get("id"), "error": str(exc)}})
        self._check_cancel()

        # 4. 评分与汇总
        self.progress_cb(95, "评分与汇总")
        self.alerts.sort(key=lambda a: a["time_start"])
        total, level = normalize(self.alerts)
        summary = {
            "risk_score": total,
            "risk_level": level,
            "severity_counts": severity_counts(self.alerts),
            "protocol_stats": self.protocol_stats,
            "parse_stats": self.parse_stats,
            "timeline": self._timeline(),
        }
        self.progress_cb(100, "完成")
        evidence = [e for a in self.alerts for e in a.get("_evidence", [])]
        return {
            "packets": [_packet_row(r) for r in records],
            "sessions": session_rows,
            "alerts": self.alerts,      # 每告警内保留 _evidence，由持久化层落库
            "evidence": evidence,       # 兼容顶层证据视图
            "summary": summary,
        }

    def _parse_progress(self, percent: int, total: int) -> None:
        # 解析期间也响应取消（大文件不再"取消无响应"）
        self._check_cancel()
        self.progress_cb(5 + int(percent * 0.38), "解析流量文件")

    def _timeline(self) -> list[dict]:
        if not self.alerts:
            return []
        lo = min(a["time_start"] for a in self.alerts)
        hi = max(a["time_end"] for a in self.alerts)
        span = max(hi - lo, 1.0)
        buckets: list[dict] = []
        for i in range(10):
            buckets.append({"ts": lo + span * i / 10, "count": 0, "score": 0.0, "max_severity": "info"})
        rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        for a in self.alerts:
            idx = min(9, int((a["time_start"] - lo) / span * 10))
            b = buckets[idx]
            b["count"] += 1
            b["score"] += a["raw_score"]
            if rank.get(a["severity"], 0) > rank.get(b["max_severity"], 0):
                b["max_severity"] = a["severity"]
        for b in buckets:
            b["score"] = round(b["score"], 2)
        return buckets

    # ------------------------------------------------------------------
    def _evaluate_strategy(self, strat: dict, records, flows) -> None:
        sid = strat["id"]
        scope = strat.get("scope", "packet")
        if scope == "correlation":
            # correlation 暂无独立执行器，发布门禁已拒绝；防御性跳过
            return
        severity = strat.get("severity", "medium")
        if self.severity_threshold and severity != "critical":
            rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            if rank.get(severity, 0) < rank.get(self.severity_threshold, 0):
                return
        conds = strat.get("conditions", {})
        window = strat.get("window") or {}
        multi = window.get("multi") or None

        if scope == "packet":
            self._eval_packet_scope(sid, strat, conds, records)
            return

        group_by = window.get("group_by") or self._default_group_by(scope)
        groups = self._groups(records, group_by, window.get("seconds"), multi)
        self._eval_group_scope(sid, strat, conds, groups)

    def _groups(self, records, group_by: list[str], seconds, multi):
        """按 (group_by, window) 缓存分组结果，避免每条策略重复扫描全部包。"""
        key = (tuple(group_by), seconds, tuple(multi) if multi else None)
        if key not in self._groups_cache:
            self._groups_cache[key] = build_groups(records, group_by, seconds, multi,
                                                   dns_map=self.dns_map)
        return self._groups_cache[key]

    @staticmethod
    def _default_group_by(scope: str) -> list[str]:
        if scope == "session":
            return ["session.key"]
        if scope == "host":
            return ["ip.src"]
        return []  # file: 单组

    # ------------------------------------------------------------------
    def _eval_packet_scope(self, sid: str, strat: dict, conds, records) -> None:
        for i, rec in enumerate(records):
            if i % _CANCEL_CHECK_EVERY == 0:
                self._check_cancel()
            hit, hits = evaluate_condition_tree(conds, packet_values(rec))
            if not hit:
                continue
            alert = self._mk_alert(strat, scope="packet", key_values={},
                                   src=rec.src_ip, dst=rec.dst_ip,
                                   src_port=rec.src_port, dst_port=rec.dst_port,
                                   protocol=rec.protocol, domain=rec.dns_query or rec.tls_sni,
                                   time_start=rec.timestamp, time_end=rec.timestamp,
                                   packet_count=1, byte_count=rec.length,
                                   frames=[rec.frame_number], hits=hits, stats={},
                                   dedup_key=f"{sid}|packet:{rec.frame_number}")
            self._append_alert(alert, sid)

    def _eval_group_scope(self, sid: str, strat: dict, conds, groups) -> None:
        for group in groups:
            if not group.packets:
                continue
            values = group.values(strat.get("scope", "session"))
            hit, hits = evaluate_condition_tree(conds, values)
            if not hit:
                continue
            kv = group.key_values
            src = kv.get("ip.src") or (group.packets[0].src_ip if group.packets else None)
            dst = kv.get("ip.dst") or (group.packets[0].dst_ip if group.packets else None)
            domain = kv.get("dns.base_domain") or next(
                (p.dns_query for p in group.packets if p.dns_query), None)
            # 代表包：优先取带端口的包；协议取组内主协议
            protos = Counter(p.protocol for p in group.packets)
            proto = protos.most_common(1)[0][0] if protos else "other"
            p0 = next((p for p in group.packets if p.src_port is not None), group.packets[0])
            cm = context_multiplier(strat.get("category", ""),
                                    values.get("session.distinct_dst_ips", 1),
                                    values.get("session.distinct_dst_ports", 1))
            # 去重键：策略 + 规范化分组键 + 时间桶（跨窗口不合并，多窗口重叠才择强）
            group_text = "|".join(f"{k}={v}" for k, v in kv.items() if v is not None)
            dedup_key = f"{sid}|group:{group_text}|bucket:{group.bucket_key or 'all'}"
            alert = self._mk_alert(
                strat, scope=strat.get("scope", "session"), key_values=kv,
                src=src, dst=dst, src_port=p0.src_port, dst_port=p0.dst_port,
                protocol=proto, domain=domain,
                time_start=values.get("session.first_ts", 0.0),
                time_end=values.get("session.last_ts", 0.0),
                packet_count=values.get("session.packet_count", 0),
                byte_count=values.get("session.byte_count", 0),
                frames=group.frame_numbers[:EVIDENCE_FRAMES],
                hits=hits, stats=group.stats(),
                context_multiplier=cm, dedup_key=dedup_key)
            self._append_alert(alert, sid)

    # ------------------------------------------------------------------
    def _mk_alert(self, strat: dict, *, scope: str, key_values: dict, src, dst,
                  src_port, dst_port, protocol, domain, time_start, time_end,
                  packet_count, byte_count, frames, hits, stats,
                  context_multiplier: float = 1.0, dedup_key: str = "") -> dict:
        weight = float(strat.get("weight", 10))
        confidence = float(strat.get("confidence", 1.0))
        severity = strat.get("severity", "medium")
        group_text = "|".join(f"{k}={v}" for k, v in key_values.items() if v is not None)
        hit_fields = [{"field": h.get("field"), "op": h.get("op"),
                       "expected": h.get("expected"), "actual": h.get("actual")} for h in hits]
        alert = {
            "task_id": "",
            "strategy_id": strat["id"],
            "strategy_version": str(strat.get("version", "")),
            "strategy_name": strat.get("name", strat["id"]),
            "category": strat.get("category", ""),
            "severity": severity,
            "raw_score": hit_score(weight, confidence, severity, context_multiplier),
            "normalized_score": 0.0,
            "confidence": confidence,
            "scope": scope,
            "group_key_text": group_text,
            "_dedup_key": dedup_key or f"{strat['id']}|{scope}:{group_text}",
            "src_ip": src, "dst_ip": dst,
            "src_port": src_port, "dst_port": dst_port,
            "protocol": protocol,
            "domain": domain,
            "time_start": time_start, "time_end": time_end,
            "packet_count": packet_count, "byte_count": byte_count,
            "hit_fields": hit_fields,
            "evidence_packets": frames,
            "stats": stats,
            "description": strat.get("description", ""),
            "false_positive_hint": strat.get("false_positive_hint", ""),
            "mitre_tags": strat.get("mitre_tags", []),
            "status": "pending",
        }
        # 证据行随告警携带，持久化时写入 alert_evidence（alert_id 在落库时回填）
        alert["_evidence"] = [{
            "task_id": "",
            "alert_id": 0,  # 持久化时回填
            "frame_number": frames[0] if frames else 0,
            "field": str(h.get("field", "")),
            "actual_value": str(h.get("actual", "")),
            "expected": str(h.get("expected", "")),
            "op": str(h.get("op", "")),
        } for h in hits]
        return alert

    @staticmethod
    def _stronger(new: dict, old: dict) -> bool:
        """同策略同去重键下，保留更强者：分数优先，其次窗口内 SYN/包数量。"""
        if new["raw_score"] != old["raw_score"]:
            return new["raw_score"] > old["raw_score"]
        n_syn = new.get("stats", {}).get("syn_count", 0) or 0
        o_syn = old.get("stats", {}).get("syn_count", 0) or 0
        if n_syn != o_syn:
            return n_syn > o_syn
        n_pkt = new.get("stats", {}).get("packet_count", 0) or 0
        o_pkt = old.get("stats", {}).get("packet_count", 0) or 0
        return n_pkt > o_pkt

    def _append_alert(self, alert: dict, sid: str) -> None:
        # 去重：同一策略同一去重键（实体 + 时间桶）保留最强窗口；不同包/不同时间桶各自保留
        key = alert["_dedup_key"]
        for existing in self.alerts:
            if existing.get("_dedup_key") == key:
                if self._stronger(alert, existing):
                    existing.update(alert)
                return
        if len(self.alerts) < MAX_ALERTS_PER_STRATEGY * len(self.strategies):
            self.alerts.append(alert)
        else:
            log.warning("alert cap reached", extra={"extra_fields": {"strategy": sid}})


def run_analysis(file_path: str, strategies: list[dict], **kwargs) -> dict:
    return AnalysisEngine(file_path, strategies, **kwargs).run()
