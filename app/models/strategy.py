"""策略库模型（文档 6.x）：策略基础信息 + 不可变版本。"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, utcnow

# 策略生命周期：draft → validated → published → disabled → archived（文档 6.6）
STRATEGY_STATUSES = ("draft", "validated", "published", "disabled", "archived")
SCOPES = ("packet", "session", "host", "file", "correlation")
SEVERITIES = ("info", "low", "medium", "high", "critical")


class Strategy(TimestampMixin, Base):
    __tablename__ = "strategies"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # 如 scan.tcp_syn_scan
    name: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(32), index=True)
    scope: Mapped[str] = mapped_column(String(16), default="packet")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    current_version: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)  # 当前发布版本
    description: Mapped[str] = mapped_column(Text, default="")
    author: Mapped[str] = mapped_column(String(64), default="builtin")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow, onupdate=utcnow)


class StrategyVersion(Base):
    __tablename__ = "strategy_versions"
    __table_args__ = (
        UniqueConstraint("strategy_id", "version", name="uq_strategy_versions_strategy_id_version"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    strategy_id: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[str] = mapped_column(String(16))            # 语义化版本 1.0.0
    status: Mapped[str] = mapped_column(String(16), default="draft", index=True)
    content: Mapped[dict] = mapped_column(JSON)                 # 完整策略定义
    validation_errors: Mapped[list] = mapped_column(JSON, default=list)
    published_by: Mapped[str] = mapped_column(String(64), default="")
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
