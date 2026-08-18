"""结果查询服务：告警、会话、包、时间线、汇总（文档 8.6/10.3）。"""
from __future__ import annotations

from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.models import Alert, AlertEvidence, Packet, Session as FlowSession
from app.services.tasks import task_service


def alert_to_dict(a: Alert, evidence: Optional[list[AlertEvidence]] = None) -> dict:
    d = {
        "id": a.id, "task_id": a.task_id, "strategy_id": a.strategy_id,
        "strategy_version": a.strategy_version, "strategy_name": a.strategy_name,
        "category": a.category, "severity": a.severity,
        "raw_score": a.raw_score, "normalized_score": a.normalized_score,
        "confidence": a.confidence, "scope": a.scope,
        "group_key_text": a.group_key_text, "src_ip": a.src_ip, "dst_ip": a.dst_ip,
        "src_port": a.src_port, "dst_port": a.dst_port, "protocol": a.protocol,
        "domain": a.domain, "time_start": a.time_start, "time_end": a.time_end,
        "packet_count": a.packet_count, "byte_count": a.byte_count,
        "hit_fields": a.hit_fields, "evidence_packets": a.evidence_packets,
        "stats": a.stats, "description": a.description,
        "false_positive_hint": a.false_positive_hint, "mitre_tags": a.mitre_tags,
        "status": a.status, "marked_by": a.marked_by, "marked_at": a.marked_at,
        "marked_note": a.marked_note,
    }
    if evidence is not None:
        d["evidence"] = [{"id": e.id, "frame_number": e.frame_number, "field": e.field,
                          "actual_value": e.actual_value, "expected": e.expected,
                          "op": e.op} for e in evidence]
    return d


def session_to_dict(s: FlowSession) -> dict:
    return {
        "session_key": s.session_key, "src_ip": s.src_ip, "dst_ip": s.dst_ip,
        "src_port": s.src_port, "dst_port": s.dst_port, "protocol": s.protocol,
        "packet_count": s.packet_count, "byte_count": s.byte_count,
        "payload_bytes": s.payload_bytes, "first_ts": s.first_ts, "last_ts": s.last_ts,
        "duration": s.duration, "syn_count": s.syn_count, "synack_count": s.synack_count,
        "rst_count": s.rst_count, "ack_count": s.ack_count,
        "completed_handshake": s.completed_handshake, "dns_query_count": s.dns_query_count,
        "http_request_count": s.http_request_count, "tls_handshake_count": s.tls_handshake_count,
        "payload_ratio": s.payload_ratio, "periodicity_score": s.periodicity_score,
        "avg_packet_size": s.avg_packet_size,
    }


def packet_to_dict(p: Packet) -> dict:
    return {
        "frame_number": p.frame_number, "timestamp": p.timestamp,
        "src_mac": p.src_mac, "dst_mac": p.dst_mac, "src_ip": p.src_ip, "dst_ip": p.dst_ip,
        "protocol": p.protocol, "ip_proto": p.ip_proto,
        "src_port": p.src_port, "dst_port": p.dst_port,
        "length": p.length, "payload_length": p.payload_length, "tcp_flags": p.tcp_flags,
        "tcp_syn": p.tcp_syn, "tcp_ack": p.tcp_ack, "tcp_rst": p.tcp_rst,
        "tcp_fin": p.tcp_fin, "tcp_push": p.tcp_push,
        "dns_query": p.dns_query, "http_method": p.http_method, "http_uri": p.http_uri,
        "http_host": p.http_host, "tls_version": p.tls_version, "tls_sni": p.tls_sni,
        "parse_warnings": p.parse_warnings,
    }


def list_alerts(session: Session, task_id: str, page: int = 1, page_size: int = 20,
                severity: str = "", strategy_id: str = "", status: str = "",
                src_ip: str = "", dst_ip: str = "", protocol: str = "",
                q: str = "") -> tuple[list[Alert], int]:
    task_service.get_task(session, task_id)
    qb = session.query(Alert).filter(Alert.task_id == task_id)
    if severity:
        qb = qb.filter(Alert.severity == severity)
    if strategy_id:
        qb = qb.filter(Alert.strategy_id == strategy_id)
    if status:
        qb = qb.filter(Alert.status == status)
    if src_ip:
        qb = qb.filter(Alert.src_ip == src_ip)
    if dst_ip:
        qb = qb.filter(Alert.dst_ip == dst_ip)
    if protocol:
        qb = qb.filter(Alert.protocol == protocol)
    total = qb.count()
    rows = qb.order_by(Alert.time_start.asc()).offset((page - 1) * page_size).limit(page_size).all()
    if q:
        rows = [r for r in rows if q.lower() in (r.group_key_text or "").lower()
                or q in (r.strategy_name or "")]
        total = len(rows)
    return rows, total


def get_alert(session: Session, task_id: str, alert_id: int) -> Alert:
    a = session.get(Alert, alert_id)
    if a is None or a.task_id != task_id:
        raise NotFoundError(f"告警不存在: {alert_id}")
    return a


def get_alert_evidence(session: Session, alert_id: int) -> list[AlertEvidence]:
    return (session.query(AlertEvidence)
            .filter(AlertEvidence.alert_id == alert_id)
            .order_by(AlertEvidence.id).all())


def list_sessions(session: Session, task_id: str, page: int = 1, page_size: int = 20,
                  src_ip: str = "", dst_ip: str = "", protocol: str = "",
                  order_by: str = "byte_count") -> tuple[list[FlowSession], int]:
    task_service.get_task(session, task_id)
    q = session.query(FlowSession).filter(FlowSession.task_id == task_id)
    if src_ip:
        q = q.filter(FlowSession.src_ip == src_ip)
    if dst_ip:
        q = q.filter(FlowSession.dst_ip == dst_ip)
    if protocol:
        q = q.filter(FlowSession.protocol == protocol)
    total = q.count()
    col = getattr(FlowSession, order_by, FlowSession.byte_count)
    rows = q.order_by(col.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return rows, total


def list_packets(session: Session, task_id: str, page: int = 1, page_size: int = 50,
                 frame_number: Optional[int] = None, src_ip: str = "", dst_ip: str = "",
                 protocol: str = "", src_port: Optional[int] = None,
                 dst_port: Optional[int] = None, start_ts: Optional[float] = None,
                 end_ts: Optional[float] = None) -> tuple[list[Packet], int]:
    task_service.get_task(session, task_id)
    q = session.query(Packet).filter(Packet.task_id == task_id)
    if frame_number is not None:
        q = q.filter(Packet.frame_number == frame_number)
    if src_ip:
        q = q.filter(Packet.src_ip == src_ip)
    if dst_ip:
        q = q.filter(Packet.dst_ip == dst_ip)
    if protocol:
        q = q.filter(Packet.protocol == protocol)
    if src_port is not None:
        q = q.filter(Packet.src_port == src_port)
    if dst_port is not None:
        q = q.filter(Packet.dst_port == dst_port)
    if start_ts is not None:
        q = q.filter(Packet.timestamp >= start_ts)
    if end_ts is not None:
        q = q.filter(Packet.timestamp <= end_ts)
    total = q.count()
    rows = q.order_by(Packet.frame_number.asc()).offset((page - 1) * page_size).limit(page_size).all()
    return rows, total


def get_packet(session: Session, task_id: str, frame_number: int) -> Packet:
    p = (session.query(Packet)
         .filter(Packet.task_id == task_id, Packet.frame_number == frame_number).first())
    if p is None:
        raise NotFoundError(f"数据包不存在: frame {frame_number}")
    return p


def task_summary(session: Session, task_id: str, alerts: Optional[list[Alert]] = None) -> dict:
    """汇总摘要。alerts 可传入已加载的告警列表，避免摘要与报告重复查询同一批告警。"""
    task = task_service.get_task(session, task_id)
    if alerts is None:
        alerts = session.query(Alert).filter(Alert.task_id == task_id).all()
    severities: dict[str, int] = {}
    hosts: dict[str, dict] = {}
    strat_hits: dict[str, dict] = {}
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for a in alerts:
        severities[a.severity] = severities.get(a.severity, 0) + 1
        for ip in (a.src_ip, a.dst_ip):
            if not ip:
                continue
            h = hosts.setdefault(ip, {"ip": ip, "alert_count": 0, "max_severity": "info",
                                      "score": 0.0, "categories": set()})
            h["alert_count"] += 1
            h["score"] += a.raw_score
            if rank.get(a.severity, 0) > rank.get(h["max_severity"], 0):
                h["max_severity"] = a.severity
            h["categories"].add(a.category)
        s = strat_hits.setdefault(a.strategy_id, {"strategy_id": a.strategy_id,
            "name": a.strategy_name, "version": a.strategy_version, "category": a.category,
            "count": 0, "max_severity": "info", "score": 0.0})
        s["count"] += 1
        s["score"] += a.raw_score
        if rank.get(a.severity, 0) > rank.get(s["max_severity"], 0):
            s["max_severity"] = a.severity
    host_list = sorted(hosts.values(), key=lambda h: h["score"], reverse=True)[:20]
    for h in host_list:
        h["categories"] = sorted(h["categories"])
        h["score"] = round(h["score"], 2)
    strat_list = sorted(strat_hits.values(), key=lambda s: s["score"], reverse=True)
    for s in strat_list:
        s["score"] = round(s["score"], 2)

    # 时间线
    timeline: list[dict] = []
    if alerts:
        lo = min(a.time_start for a in alerts)
        hi = max(a.time_end for a in alerts)
        span = max(hi - lo, 1.0)
        buckets = [{"ts": lo + span * i / 10, "count": 0, "score": 0.0,
                    "max_severity": "info"} for i in range(10)]
        for a in alerts:
            idx = min(9, int((a.time_start - lo) / span * 10))
            b = buckets[idx]
            b["count"] += 1
            b["score"] += a.raw_score
            if rank.get(a.severity, 0) > rank.get(b["max_severity"], 0):
                b["max_severity"] = a.severity
        for b in buckets:
            b["score"] = round(b["score"], 2)
        timeline = buckets

    protocol_stats = dict(session.query(Packet.protocol, func.count())
                          .filter(Packet.task_id == task_id).group_by(Packet.protocol).all())
    top_sessions = (session.query(FlowSession).filter(FlowSession.task_id == task_id)
                    .order_by(FlowSession.byte_count.desc()).limit(10).all())
    return {
        "risk": {"score": task.risk_score, "level": task.risk_level,
                 "severity_counts": severities},
        "hosts": host_list,
        "strategy_hits": strat_list,
        "timeline": timeline,
        "protocol_stats": protocol_stats,
        "top_sessions": [session_to_dict(s) for s in top_sessions],
    }


def dashboard_stats(session: Session) -> dict:
    """仪表盘聚合：全库统计，不依赖"最近一页任务"（修正前端把 6 条任务当全量的错误）。"""
    from app.models import AnalysisTask, UploadedFile

    files_total = (session.query(func.count(UploadedFile.id))
                   .filter(UploadedFile.deleted == False).scalar())  # noqa: E712
    tasks_total = (session.query(func.count(AnalysisTask.id))
                   .filter(AnalysisTask.status != "deleted").scalar())
    alerts_total = (session.query(func.count(Alert.id))
                    .join(AnalysisTask, AnalysisTask.id == Alert.task_id)
                    .filter(AnalysisTask.status != "deleted").scalar())
    max_risk = (session.query(AnalysisTask)
                .filter(AnalysisTask.status != "deleted", AnalysisTask.risk_score > 0)
                .order_by(AnalysisTask.risk_score.desc()).first())
    recent = (session.query(AnalysisTask)
              .filter(AnalysisTask.status != "deleted")
              .order_by(AnalysisTask.id.desc()).limit(6).all())
    return {
        "files": files_total or 0,
        "tasks": tasks_total or 0,
        "alerts": alerts_total or 0,
        "max_risk_task": max_risk,
        "recent_tasks": recent,
    }
