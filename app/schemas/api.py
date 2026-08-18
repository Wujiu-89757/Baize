"""请求/响应 DTO。"""
from __future__ import annotations

import math
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------- 通用
class Page(BaseModel):
    total: int
    items: list = Field(default_factory=list)
    page: int = 1
    page_size: int = 20


# ---------------------------------------------------------------- 文件
class FileOut(BaseModel):
    id: str
    original_name: str
    size_bytes: int
    sha256: str
    format: str
    status: str
    uploader_name: str
    created_at: datetime
    error_message: str = ""
    duplicate_of: Optional[str] = None


class FileDetail(FileOut):
    storage_path: str = ""
    deduplicated: bool = False


# ---------------------------------------------------------------- 策略
class StrategyMetaOut(BaseModel):
    id: str
    name: str
    category: str
    scope: str
    enabled: bool
    current_version: Optional[str] = None
    description: str = ""
    author: str = ""
    created_at: datetime
    updated_at: datetime


class StrategyVersionOut(BaseModel):
    id: int
    strategy_id: str
    version: str
    status: str
    published_by: str = ""
    published_at: Optional[datetime] = None
    created_at: datetime


class StrategyDetail(BaseModel):
    meta: StrategyMetaOut
    versions: list[StrategyVersionOut] = Field(default_factory=list)
    content: Optional[dict] = None


class StrategyUpsert(BaseModel):
    """创建/更新策略：content 或 text 二选一，服务端一次解析、校验、保存并可选发布（单事务）。"""

    content: Optional[dict] = None
    text: Optional[str] = None
    publish: bool = False
    enabled: Optional[bool] = None

    @model_validator(mode="after")
    def _source_ok(self):
        if self.content is not None and self.text is not None:
            raise ValueError("content 与 text 只能提供一个")
        if self.content is None and not (self.text and self.text.strip()):
            raise ValueError("需要提供 content 或非空 text")
        return self


class StrategyImportRequest(BaseModel):
    items: Optional[list[dict]] = None
    text: Optional[str] = None            # 多文档 YAML（--- 分隔）或 JSON 数组
    mode: Literal["create", "update", "skip"] = "create"

    @model_validator(mode="after")
    def _source_ok(self):
        if self.items is not None and self.text is not None:
            raise ValueError("items 与 text 只能提供一个")
        if self.items is None and not (self.text and self.text.strip()):
            raise ValueError("需要提供 items 或非空 text")
        if self.items == []:
            raise ValueError("items 不能为空")
        return self


class StrategyImportResult(BaseModel):
    created: list[str] = Field(default_factory=list)
    updated: list[str] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)
    errors: list[dict] = Field(default_factory=list)


class ValidateResponse(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------- 分析任务
class AnalysisCreate(BaseModel):
    file_id: str
    strategy_ids: Optional[list[str]] = None      # None = 全部启用策略
    severity_threshold: Optional[Literal["info", "low", "medium", "high", "critical"]] = None
    time_range: Optional[list[float]] = None      # [start, end] epoch 秒
    name: Optional[str] = Field(None, max_length=200)

    @field_validator("time_range")
    @classmethod
    def _check_time_range(cls, v):
        if v is None:
            return v
        if len(v) != 2:
            raise ValueError("time_range 必须是 [start, end] 两个数字")
        start, end = v[0], v[1]
        if not all(math.isfinite(x) for x in (start, end)):
            raise ValueError("time_range 必须是有限数字")
        if start > end:
            raise ValueError("time_range 的起点不能晚于终点")
        return v


class TaskOut(BaseModel):
    id: str
    file_id: str
    file_name: str = ""
    file_sha256: str = ""
    strategy_set: list = Field(default_factory=list)
    status: str
    progress: int
    stage: str
    created_by_name: str = ""
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    deleted_at: Optional[datetime] = None
    error_message: str = ""
    engine_version: str = ""
    parse_summary: dict = Field(default_factory=dict)
    config_snapshot: dict = Field(default_factory=dict)
    risk_score: float = 0.0
    risk_level: str = "info"
    alert_count: int = 0
    strategy_hits: int = 0
    retry_count: int = 0


# ---------------------------------------------------------------- 告警
class AlertOut(BaseModel):
    id: int
    task_id: str
    strategy_id: str
    strategy_version: str
    strategy_name: str
    category: str
    severity: str
    raw_score: float
    normalized_score: float
    confidence: float
    scope: str
    group_key_text: str = ""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = ""
    domain: Optional[str] = None
    time_start: float = 0.0
    time_end: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    hit_fields: list = Field(default_factory=list)
    evidence_packets: list = Field(default_factory=list)
    stats: dict = Field(default_factory=dict)
    description: str = ""
    false_positive_hint: str = ""
    mitre_tags: list = Field(default_factory=list)
    status: str = "pending"
    marked_by: Optional[int] = None
    marked_at: Optional[datetime] = None
    marked_note: str = ""
    evidence: list = Field(default_factory=list)   # 单条告警详情附带结构化证据


class AlertMarkRequest(BaseModel):
    status: Literal["pending", "confirmed", "suspected", "false_positive", "ignored"]
    note: str = Field("", max_length=2000)


class PacketOut(BaseModel):
    frame_number: int
    timestamp: float
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: str
    ip_proto: Optional[int] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    length: int
    payload_length: int
    tcp_flags: str = ""
    tcp_syn: bool = False
    tcp_ack: bool = False
    tcp_rst: bool = False
    tcp_fin: bool = False
    tcp_push: bool = False
    dns_query: Optional[str] = None
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    tls_version: Optional[str] = None
    tls_sni: Optional[str] = None
    parse_warnings: list = Field(default_factory=list)


class SummaryOut(BaseModel):
    task: TaskOut
    risk: dict  # score/level/severity_counts
    hosts: list = Field(default_factory=list)
    top_sessions: list = Field(default_factory=list)
    strategy_hits: list = Field(default_factory=list)
    timeline: list = Field(default_factory=list)
    protocol_stats: dict = Field(default_factory=dict)


class DashboardStatsOut(BaseModel):
    files: int = 0
    tasks: int = 0
    alerts: int = 0
    max_risk_task: Optional[TaskOut] = None
    recent_tasks: list[TaskOut] = Field(default_factory=list)


# ---------------------------------------------------------------- 审计
class AuditOut(BaseModel):
    id: int
    ts: datetime
    username: str
    action: str
    target_type: str
    target_id: str
    detail: dict = Field(default_factory=dict)
    ip: str = ""
