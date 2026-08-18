"""评分引擎（文档 8.4）。

hit_score = weight × confidence × severity_multiplier × context_multiplier
- 重复命中设上限：同一策略所有告警原始分合计不超过 per_strategy_score_cap；
- 任务总分不超过 score_normalization_cap，并归一化到 0~100；
- 等级：0~19 信息 / 20~39 低 / 40~69 中 / 70~89 高 / 90~100 严重。
"""
from __future__ import annotations

from typing import Any

from app.core.config import settings


def severity_multiplier(severity: str) -> float:
    return settings.severity_multipliers.get(severity, 1.0)


def hit_score(weight: float, confidence: float, severity: str,
              context_multiplier: float = 1.0) -> float:
    return round(weight * confidence * severity_multiplier(severity) * context_multiplier, 4)


def context_multiplier(category: str, distinct_dst_ips: int, distinct_dst_ports: int) -> float:
    """上下文乘数：扫描/外连类策略出现多目标扩散时小幅加权（默认 1.0）。"""
    if category in ("scanning", "outbound", "credential"):
        if distinct_dst_ips >= 5:
            return 1.1
        if distinct_dst_ports >= 50:
            return 1.05
    return 1.0


def level_of(score: float) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def normalize(alerts: list[dict]) -> tuple[float, str]:
    """单策略封顶 → 任务封顶 → 归一化 0~100（文档 8.4）。

    契约：
    - 单策略原始分合计超过 per_strategy_score_cap 时，该策略内各告警按比例缩放分摊上限；
    - 任务原始分 = 各策略封顶后合计，再按 score_normalization_cap 归一化到 0~100；
    - 风险等级基于归一化后的 0~100 分；任何输入最终分数都不超过 100。

    alerts: [{strategy_id, raw_score}]；就地写入 normalized_score。
    """
    if not alerts:
        return 0.0, "info"

    per_strategy: dict[str, float] = {}
    for a in alerts:
        per_strategy[a["strategy_id"]] = per_strategy.get(a["strategy_id"], 0.0) + a["raw_score"]

    # 单策略封顶（超限按比例缩放，保证单策略告警分数之和符合策略上限）
    capped_totals: dict[str, float] = {
        sid: min(t, settings.per_strategy_score_cap) for sid, t in per_strategy.items()
    }
    task_raw = sum(capped_totals.values())
    if task_raw <= 0:
        for a in alerts:
            a["normalized_score"] = 0.0
        return 0.0, "info"

    cap = settings.score_normalization_cap
    normalized_total = min(task_raw, cap) / cap * 100.0

    for a in alerts:
        strategy_raw = per_strategy[a["strategy_id"]]
        factor = capped_totals[a["strategy_id"]] / strategy_raw if strategy_raw else 0.0
        # 每告警归一化分 = 该告警对"任务归一化总分"的贡献占比
        a["normalized_score"] = round(a["raw_score"] * factor / task_raw * normalized_total, 4)
    return round(normalized_total, 4), level_of(normalized_total)


def severity_counts(alerts: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for a in alerts:
        counts[a["severity"]] = counts.get(a["severity"], 0) + 1
    return counts


def summarize_alerts(alerts: list[dict]) -> dict[str, Any]:
    """主机排行、策略命中统计等（供结果页）。"""
    hosts: dict[str, dict] = {}
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for a in alerts:
        for ip in (a.get("src_ip"), a.get("dst_ip")):
            if not ip:
                continue
            h = hosts.setdefault(ip, {"ip": ip, "alert_count": 0, "max_severity": "info",
                                      "score": 0.0, "categories": set()})
            h["alert_count"] += 1
            h["score"] += a.get("raw_score", 0)
            if sev_rank.get(a.get("severity"), 0) > sev_rank.get(h["max_severity"], 0):
                h["max_severity"] = a.get("severity", "info")
            h["categories"].add(a.get("category", ""))
    host_list = sorted(hosts.values(), key=lambda h: h["score"], reverse=True)[:20]
    for h in host_list:
        h["categories"] = sorted(h["categories"])
        h["score"] = round(h["score"], 2)

    strat: dict[str, dict] = {}
    for a in alerts:
        s = strat.setdefault(a["strategy_id"], {
            "strategy_id": a["strategy_id"], "name": a["strategy_name"],
            "version": a["strategy_version"], "category": a["category"],
            "count": 0, "max_severity": "info", "score": 0.0})
        s["count"] += 1
        s["score"] += a.get("raw_score", 0)
        if sev_rank.get(a.get("severity"), 0) > sev_rank.get(s["max_severity"], 0):
            s["max_severity"] = a.get("severity", "info")
    strat_list = sorted(strat.values(), key=lambda s: s["score"], reverse=True)
    for s in strat_list:
        s["score"] = round(s["score"], 2)
    return {"hosts": host_list, "strategy_hits": strat_list}
