"""审计日志服务（文档 11 可观测性/安全性）。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models import AuditLog


def log_audit(session: Session, *, user_id: Optional[int], username: str,
              action: str, target_type: str = "", target_id: str = "",
              detail: Optional[dict] = None, ip: str = "") -> AuditLog:
    entry = AuditLog(
        ts=datetime.now(timezone.utc),
        user_id=user_id,
        username=username or "-",
        action=action,
        target_type=target_type,
        target_id=str(target_id or ""),
        detail=detail or {},
        ip=ip,
    )
    session.add(entry)
    return entry


def list_audit(session: Session, page: int = 1, page_size: int = 20,
               action: str = "", username: str = "") -> tuple[list[AuditLog], int]:
    q = session.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action == action)
    if username:
        q = q.filter(AuditLog.username == username)
    total = q.count()
    rows = q.order_by(AuditLog.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return rows, total
