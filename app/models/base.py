"""SQLAlchemy 声明式基类与通用列。"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now())


class StringUUIDMixin:
    """主键使用 UUID 字符串，便于跨系统传递。"""

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=None)
