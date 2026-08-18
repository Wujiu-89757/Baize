"""分析任务模型（文档 8.1）。"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin

TASK_STATUSES = ("queued", "running", "succeeded", "failed", "cancelled", "deleted")


class AnalysisTask(TimestampMixin, Base):
    __tablename__ = "analysis_tasks"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    file_id: Mapped[str] = mapped_column(String(40), index=True)
    file_sha256: Mapped[str] = mapped_column(String(64), default="")
    strategy_set: Mapped[list] = mapped_column(JSON, default=list)   # [{id, version}]
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    stage: Mapped[str] = mapped_column(String(64), default="queued")
    created_by: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_by_name: Mapped[str] = mapped_column(String(64), default="-")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str] = mapped_column(Text, default="")
    engine_version: Mapped[str] = mapped_column(String(64), default="")
    config_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    parse_summary: Mapped[dict] = mapped_column(JSON, default=dict)  # 包/会话/警告统计
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), default="info")
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    strategy_hits: Mapped[int] = mapped_column(Integer, default=0)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
