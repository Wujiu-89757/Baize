"""审计日志接口（本地模式：无需权限）。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.schemas.api import AuditOut, Page
from app.services import audit

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("", response_model=Page)
def list_audit(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=200),
               action: str = "", username: str = "",
               db: Session = Depends(get_db), _user=Depends(get_current_user)):
    rows, total = audit.list_audit(db, page, page_size, action, username)
    return Page(total=total,
                items=[AuditOut(id=r.id, ts=r.ts, username=r.username, action=r.action,
                                target_type=r.target_type, target_id=r.target_id,
                                detail=r.detail, ip=r.ip) for r in rows],
                page=page, page_size=page_size)
