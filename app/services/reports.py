"""报告导出服务（文档 8.6/14）：JSON、CSV、HTML。报告包含文件哈希、引擎版本、策略版本。"""
from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Alert, AlertEvidence, AnalysisTask, Packet
from app.services import queries
from app.services.tasks import task_service


def _base_meta(session: Session, task: AnalysisTask) -> dict:
    from app.models import UploadedFile
    f = session.get(UploadedFile, task.file_id)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "engine_version": task.engine_version or settings.engine_version,
        "file": {
            "id": task.file_id,
            "name": f.original_name if f else "",
            "sha256": task.file_sha256 or (f.sha256 if f else ""),
            "size_bytes": f.size_bytes if f else 0,
            "format": f.format if f else "",
        },
        "strategy_set": task.strategy_set,
        "config_snapshot": task.config_snapshot,
    }


def _load_alerts(session: Session, task_id: str) -> list[Alert]:
    """一次查询加载全部告警，供摘要与各格式渲染共享（避免重复加载同一批数据）。"""
    return session.query(Alert).filter(Alert.task_id == task_id).order_by(Alert.time_start).all()


def export_json(session: Session, task_id: str, include_packets: bool = True,
                packet_limit: int = 50000) -> dict:
    task = task_service.get_task(session, task_id)
    alerts = _load_alerts(session, task_id)
    evidence = session.query(AlertEvidence).filter(AlertEvidence.task_id == task_id).all()
    sessions = (session.query(queries.FlowSession)
                .filter(queries.FlowSession.task_id == task_id)
                .order_by(queries.FlowSession.byte_count.desc()).all())
    doc: dict = {
        "meta": _base_meta(session, task),
        "summary": queries.task_summary(session, task_id, alerts),
        "task": {
            "id": task.id, "status": task.status, "risk_score": task.risk_score,
            "risk_level": task.risk_level, "alert_count": task.alert_count,
            "parse_summary": task.parse_summary, "created_at": task.created_at.isoformat(),
            "finished_at": task.finished_at.isoformat() if task.finished_at else None,
        },
        "alerts": [queries.alert_to_dict(a) for a in alerts],
        "evidence": [{"alert_id": e.alert_id, "frame_number": e.frame_number,
                      "field": e.field, "actual_value": e.actual_value,
                      "expected": e.expected, "op": e.op} for e in evidence],
        "sessions": [queries.session_to_dict(s) for s in sessions],
    }
    if include_packets:
        rows = session.query(Packet).filter(Packet.task_id == task_id).order_by(
            Packet.frame_number).limit(packet_limit).all()
        doc["packets"] = [queries.packet_to_dict(p) for p in rows]
        if len(rows) >= packet_limit:
            doc["packets_truncated"] = True
    return doc


def export_alerts_csv(session: Session, task_id: str) -> str:
    task_service.get_task(session, task_id)
    alerts = session.query(Alert).filter(Alert.task_id == task_id).order_by(Alert.time_start).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["alert_id", "time_start", "time_end", "severity", "raw_score",
                     "normalized_score", "strategy_id", "strategy_version", "strategy_name",
                     "category", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                     "domain", "group_key", "packet_count", "byte_count",
                     "evidence_frames", "status", "description"])
    for a in alerts:
        writer.writerow([
            a.id, a.time_start, a.time_end, a.severity, a.raw_score, a.normalized_score,
            a.strategy_id, a.strategy_version, a.strategy_name, a.category,
            a.src_ip or "", a.dst_ip or "", a.src_port or "", a.dst_port or "",
            a.protocol, a.domain or "", a.group_key_text, a.packet_count, a.byte_count,
            ";".join(map(str, a.evidence_packets or [])), a.status, a.description,
        ])
    return buf.getvalue()


def export_packets_csv(session: Session, task_id: str, limit: int = 50000) -> str:
    task_service.get_task(session, task_id)
    rows = session.query(Packet).filter(Packet.task_id == task_id).order_by(
        Packet.frame_number).limit(limit).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["frame_number", "timestamp", "src_ip", "dst_ip", "protocol",
                     "src_port", "dst_port", "length", "payload_length", "tcp_flags",
                     "dns_query", "http_method", "http_uri", "tls_version", "tls_sni"])
    for p in rows:
        writer.writerow([p.frame_number, p.timestamp, p.src_ip or "", p.dst_ip or "",
                         p.protocol, p.src_port or "", p.dst_port or "", p.length,
                         p.payload_length, p.tcp_flags, p.dns_query or "",
                         p.http_method or "", p.http_uri or "", p.tls_version or "",
                         p.tls_sni or ""])
    return buf.getvalue()


def export_html(session: Session, task_id: str) -> str:
    task = task_service.get_task(session, task_id)
    orm_alerts = _load_alerts(session, task_id)
    alerts = [queries.alert_to_dict(a) for a in orm_alerts]
    summary = queries.task_summary(session, task_id, orm_alerts)
    evidence = session.query(AlertEvidence).filter(AlertEvidence.task_id == task_id).all()
    ev_map: dict[int, list] = {}
    for e in evidence:
        ev_map.setdefault(e.alert_id, []).append(e)
    meta = _base_meta(session, task)
    risk = summary.get("risk", {})
    level_cn = {"info": "信息", "low": "低风险", "medium": "中风险", "high": "高风险", "critical": "严重"}
    sev_cn = {"info": "信息", "low": "低", "medium": "中", "high": "高", "critical": "严重"}
    sev_color = {"info": "#8a94a6", "low": "#2f9e44", "medium": "#f59f00",
                 "high": "#f76707", "critical": "#e03131"}

    alert_rows = []
    for a in alerts:
        evs = ev_map.get(a["id"], [])
        ev_html = "".join(
            f"<tr><td>{html.escape(e.field)}</td><td>{html.escape(e.op)}</td>"
            f"<td>{html.escape(e.expected)}</td><td><code>{html.escape(e.actual_value)}</code></td>"
            f"<td>{e.frame_number}</td></tr>" for e in evs)
        hit_html = "".join(
            f"<span class='hit'>{html.escape(str(h.get('field')))} {html.escape(str(h.get('op')))} "
            f"≈ {html.escape(str(h.get('actual')))}</span>" for h in (a.get("hit_fields") or []))
        alert_rows.append(f"""
        <tr>
          <td>{a['id']}</td>
          <td><span class="badge" style="background:{sev_color.get(a['severity'], '#888')}">{sev_cn.get(a['severity'], a['severity'])}</span></td>
          <td>{html.escape(a['strategy_name'])} <small>v{html.escape(a['strategy_version'])}</small></td>
          <td>{html.escape(a['src_ip'] or '-')} → {html.escape(a['dst_ip'] or '-')} :{html.escape(str(a['dst_port'] or '-'))}</td>
          <td>{a['raw_score']:.2f} → {a['normalized_score']:.2f}</td>
          <td>{a['evidence_packets'] and ','.join(map(str, a['evidence_packets'][:5])) or '-'}</td>
          <td><details><summary>证据</summary>{hit_html}<table class="ev"><thead><tr><th>字段</th><th>算子</th><th>期望</th><th>实际值</th><th>帧号</th></tr></thead><tbody>{ev_html}</tbody></table></details></td>
        </tr>""")

    tl = summary.get("timeline") or []
    max_count = max((b["count"] for b in tl), default=1) or 1
    tl_html = "".join(
        f"<div class='tl-col' title='{b['count']} 条告警' style='height:{max(4, int(b['count']/max_count*80))}px'></div>"
        for b in tl)

    hosts = summary.get("hosts") or []
    host_rows = "".join(
        f"<tr><td>{html.escape(h['ip'])}</td><td>{h['alert_count']}</td>"
        f"<td><span class='badge' style='background:{sev_color.get(h['max_severity'], '#888')}'>{sev_cn.get(h['max_severity'], h['max_severity'])}</span></td>"
        f"<td>{h['score']:.2f}</td><td>{html.escape(', '.join(h['categories']))}</td></tr>"
        for h in hosts[:15])

    strat_rows = "".join(
        f"<tr><td>{html.escape(s['strategy_id'])}</td><td>{html.escape(s['name'])}</td><td>v{html.escape(s['version'])}</td>"
        f"<td>{s['count']}</td><td>{s['score']:.2f}</td></tr>"
        for s in (summary.get("strategy_hits") or []))

    sev_counts = "".join(
        f"<span class='badge' style='background:{sev_color.get(k, '#888')}'>{sev_cn.get(k, k)}: {v}</span> "
        for k, v in (risk.get("severity_counts") or {}).items())

    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>白泽流量分析报告 - {task.id}</title>
<style>
  body {{ font-family: "Microsoft YaHei", sans-serif; margin: 0; background: #f4f6fb; color: #1f2430; }}
  header {{ background: linear-gradient(135deg, #1b2a4a, #274b8f); color: #fff; padding: 24px 40px; }}
  header h1 {{ margin: 0 0 6px; font-size: 22px; }}
  .meta {{ color: #c7d4ea; font-size: 13px; line-height: 1.8; }}
  main {{ padding: 24px 40px; max-width: 1200px; margin: 0 auto; }}
  .cards {{ display: flex; gap: 16px; margin: 20px 0; flex-wrap: wrap; }}
  .card {{ background: #fff; border-radius: 10px; padding: 16px 20px; box-shadow: 0 1px 4px rgba(0,0,0,.08); flex: 1; min-width: 180px; }}
  .card .num {{ font-size: 30px; font-weight: 700; }}
  .card .lbl {{ color: #667; font-size: 13px; margin-top: 4px; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; color: #fff; font-size: 12px; margin: 2px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; font-size: 13px; }}
  th, td {{ padding: 8px 10px; border-bottom: 1px solid #eef1f6; text-align: left; vertical-align: top; }}
  th {{ background: #f0f3fa; }}
  .hit {{ display: inline-block; background: #fff3bf; padding: 2px 8px; border-radius: 6px; margin: 2px; font-size: 12px; }}
  .ev {{ margin-top: 6px; font-size: 12px; }}
  .ev code {{ background: #f1f3f5; padding: 1px 4px; border-radius: 4px; }}
  .tl {{ display: flex; align-items: flex-end; gap: 6px; height: 90px; padding: 8px; background: #fff; border-radius: 8px; }}
  .tl-col {{ flex: 1; background: linear-gradient(#4dabf7, #1971c2); border-radius: 3px 3px 0 0; }}
  section {{ margin: 26px 0; }}
  h2 {{ font-size: 16px; border-left: 4px solid #274b8f; padding-left: 10px; }}
  .warn {{ color: #b08900; font-size: 12px; }}
</style></head><body>
<header>
  <h1>白泽流量分析平台 · 分析报告</h1>
  <div class="meta">
    任务 ID：{task.id} ｜ 状态：{task.status}<br>
    输入文件：{html.escape(meta['file'].get('name', ''))}（{meta['file'].get('format', '')}，{meta['file'].get('size_bytes', 0)} 字节）<br>
    SHA-256：<code>{meta['file'].get('sha256', '')}</code><br>
    引擎版本：{html.escape(meta['engine_version'])} ｜ 生成时间：{html.escape(meta['generated_at'])}<br>
    策略集：{html.escape(json.dumps(meta['strategy_set'], ensure_ascii=False))}
  </div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="num" style="color:{sev_color.get(risk.get('level'), '#333')}">{risk.get('score', 0):.1f}</div><div class="lbl">风险总分（{level_cn.get(risk.get('level'), risk.get('level'))}）</div></div>
    <div class="card"><div class="num">{task.alert_count}</div><div class="lbl">告警数 {sev_counts}</div></div>
    <div class="card"><div class="num">{task.parse_summary.get('packets', 0)}</div><div class="lbl">数据包</div></div>
    <div class="card"><div class="num">{task.parse_summary.get('sessions', 0)}</div><div class="lbl">会话</div></div>
    <div class="card"><div class="num">{len(hosts)}</div><div class="lbl">涉及主机</div></div>
  </div>

  <section><h2>告警时间线</h2><div class="tl">{tl_html}</div></section>

  <section><h2>涉及主机</h2><table><thead><tr><th>主机</th><th>告警数</th><th>最高级别</th><th>累计分</th><th>类别</th></tr></thead><tbody>{host_rows}</tbody></table></section>

  <section><h2>策略命中统计</h2><table><thead><tr><th>策略</th><th>名称</th><th>版本</th><th>命中</th><th>累计分</th></tr></thead><tbody>{strat_rows}</tbody></table></section>

  <section><h2>告警明细</h2>
  <p class="warn">注意：所有告警均为"疑似"，需结合原始流量（Wireshark 对照 frame number）与业务基线确认。分数仅辅助判断。</p>
  <table><thead><tr><th>ID</th><th>级别</th><th>策略</th><th>源→目的</th><th>原始分→归一化</th><th>代表帧</th><th>证据</th></tr></thead><tbody>{alert_rows}</tbody></table></section>
</main>
</body></html>"""
