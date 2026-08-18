"""分析结果模型：标准化包、会话、告警与证据（文档 8.3/8.5、9）。"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

# ---------------------------------------------------------------------------
# 标准化数据包索引（不保存载荷，文档 9：大载荷不建议全部入库）
# ---------------------------------------------------------------------------


class Packet(Base):
    __tablename__ = "packets"
    __table_args__ = ({"sqlite_autoincrement": True},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(String(40), index=True)
    frame_number: Mapped[int] = mapped_column(Integer, index=True)
    timestamp: Mapped[float] = mapped_column(Float, index=True)      # epoch 秒
    src_mac: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    dst_mac: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    src_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    protocol: Mapped[str] = mapped_column(String(16), default="other")
    ip_proto: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    length: Mapped[int] = mapped_column(Integer, default=0)
    payload_length: Mapped[int] = mapped_column(Integer, default=0)
    tcp_flags: Mapped[str] = mapped_column(String(8), default="")    # 如 "S"、"SA"、"R"、"A"
    tcp_syn: Mapped[bool] = mapped_column(Boolean, default=False)
    tcp_ack: Mapped[bool] = mapped_column(Boolean, default=False)
    tcp_rst: Mapped[bool] = mapped_column(Boolean, default=False)
    tcp_fin: Mapped[bool] = mapped_column(Boolean, default=False)
    tcp_push: Mapped[bool] = mapped_column(Boolean, default=False)
    dns_query: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    dns_qtype: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dns_response: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    dns_rcode: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dns_answers: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    http_method: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    http_uri: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    http_host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    http_user_agent: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    http_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    http_response: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    http_body_head: Mapped[Optional[str]] = mapped_column(Text, nullable=True)     # HTTP 体前缀
    tcp_payload_head: Mapped[Optional[str]] = mapped_column(Text, nullable=True)   # 未识别 TCP 载荷前缀
    tls_version: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    tls_sni: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tls_handshake_type: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    icmp_type: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    parse_warnings: Mapped[list] = mapped_column(JSON, default=list)


# ---------------------------------------------------------------------------
# 会话（五元组聚合）
# ---------------------------------------------------------------------------


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = ({"sqlite_autoincrement": True},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(String(40), index=True)
    session_key: Mapped[str] = mapped_column(String(200), index=True)  # src_ip|dst_ip|src_port|dst_port|proto
    src_ip: Mapped[str] = mapped_column(String(64), index=True)
    dst_ip: Mapped[str] = mapped_column(String(64), index=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16))
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    byte_count: Mapped[int] = mapped_column(Integer, default=0)
    payload_bytes: Mapped[int] = mapped_column(Integer, default=0)
    first_ts: Mapped[float] = mapped_column(Float, default=0.0)
    last_ts: Mapped[float] = mapped_column(Float, default=0.0)
    duration: Mapped[float] = mapped_column(Float, default=0.0)
    syn_count: Mapped[int] = mapped_column(Integer, default=0)
    pure_syn_count: Mapped[int] = mapped_column(Integer, default=0)
    synack_count: Mapped[int] = mapped_column(Integer, default=0)
    ack_count: Mapped[int] = mapped_column(Integer, default=0)
    rst_count: Mapped[int] = mapped_column(Integer, default=0)
    fin_count: Mapped[int] = mapped_column(Integer, default=0)
    other_count: Mapped[int] = mapped_column(Integer, default=0)
    completed_handshake: Mapped[bool] = mapped_column(Boolean, default=False)
    rst_after_synack_count: Mapped[int] = mapped_column(Integer, default=0)
    dns_query_count: Mapped[int] = mapped_column(Integer, default=0)
    http_request_count: Mapped[int] = mapped_column(Integer, default=0)
    tls_handshake_count: Mapped[int] = mapped_column(Integer, default=0)
    payload_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    interval_mean_ms: Mapped[float] = mapped_column(Float, default=0.0)
    interval_stddev_ms: Mapped[float] = mapped_column(Float, default=0.0)
    periodicity_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0~1，1 为完全周期
    avg_packet_size: Mapped[float] = mapped_column(Float, default=0.0)


# ---------------------------------------------------------------------------
# 告警与证据（文档 8.5）
# ---------------------------------------------------------------------------

ALERT_STATUSES = ("pending", "confirmed", "suspected", "false_positive", "ignored")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = ({"sqlite_autoincrement": True},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(String(40), index=True)
    strategy_id: Mapped[str] = mapped_column(String(64), index=True)
    strategy_version: Mapped[str] = mapped_column(String(16), default="")
    strategy_name: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    raw_score: Mapped[float] = mapped_column(Float, default=0.0)
    normalized_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    scope: Mapped[str] = mapped_column(String(16), default="session")
    group_key_text: Mapped[str] = mapped_column(String(255), default="")
    src_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16), default="")
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    time_start: Mapped[float] = mapped_column(Float, default=0.0)
    time_end: Mapped[float] = mapped_column(Float, default=0.0)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    byte_count: Mapped[int] = mapped_column(Integer, default=0)
    hit_fields: Mapped[list] = mapped_column(JSON, default=list)     # [{field,value,expected,op}]
    evidence_packets: Mapped[list] = mapped_column(JSON, default=list)  # 代表帧号列表
    stats: Mapped[dict] = mapped_column(JSON, default=dict)          # 策略自定义证据（扫描统计等）
    description: Mapped[str] = mapped_column(Text, default="")
    false_positive_hint: Mapped[str] = mapped_column(Text, default="")
    mitre_tags: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    marked_by: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    marked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    marked_note: Mapped[str] = mapped_column(Text, default="")


class AlertEvidence(Base):
    __tablename__ = "alert_evidence"
    __table_args__ = ({"sqlite_autoincrement": True},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[int] = mapped_column(Integer, index=True)
    task_id: Mapped[str] = mapped_column(String(40), index=True)
    frame_number: Mapped[int] = mapped_column(Integer, default=0)
    field: Mapped[str] = mapped_column(String(64))
    actual_value: Mapped[str] = mapped_column(Text, default="")
    expected: Mapped[str] = mapped_column(Text, default="")
    op: Mapped[str] = mapped_column(String(24), default="")
