"""分析任务与结果接口（文档 8.6）。"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_current_user, get_db
from app.models import UploadedFile
from app.schemas.api import (AlertMarkRequest, AlertOut, AnalysisCreate, DashboardStatsOut,
                             PacketOut, Page, SummaryOut, TaskOut)
from app.services import audit, queries, reports
from app.services.tasks import task_service

router = APIRouter(prefix="/api/v1/analysis", tags=["analysis"])

_PAGE = Query(1, ge=1)
_PAGE_SIZE = Query(20, ge=1, le=200)


def _file_names(db: Session, rows) -> dict:
    """一次查询批量取得任务文件显示名（避免逐任务 N+1）。"""
    ids = {r.file_id for r in rows if r.file_id}
    if not ids:
        return {}
    found = db.query(UploadedFile.id, UploadedFile.original_name).filter(
        UploadedFile.id.in_(ids)).all()
    return {fid: name for fid, name in found}


def _task_out(db: Session, row, fname: Optional[str] = None) -> TaskOut:
    if fname is None:
        f = db.get(UploadedFile, row.file_id)
        fname = f.original_name if f else ""
    return TaskOut(
        id=row.id, file_id=row.file_id, file_name=fname, file_sha256=row.file_sha256,
        strategy_set=row.strategy_set, status=row.status, progress=row.progress,
        stage=row.stage, created_by_name=row.created_by_name,
        created_at=row.created_at, started_at=row.started_at, finished_at=row.finished_at,
        deleted_at=row.deleted_at, error_message=row.error_message,
        engine_version=row.engine_version, parse_summary=row.parse_summary,
        config_snapshot=row.config_snapshot, risk_score=row.risk_score,
        risk_level=row.risk_level, alert_count=row.alert_count,
        strategy_hits=row.strategy_hits, retry_count=row.retry_count,
    )


@router.get("/stats", response_model=DashboardStatsOut)
def dashboard_stats(db: Session = Depends(get_db),
                    user=Depends(get_current_user)):
    """仪表盘聚合统计（轻量接口，前端不再把"最近 6 条任务"当作全库累计）。"""
    stats = queries.dashboard_stats(db)
    names = _file_names(db, [t for t in (stats["recent_tasks"] + ([stats["max_risk_task"]] if stats["max_risk_task"] else [])) if t])
    return DashboardStatsOut(
        files=stats["files"], tasks=stats["tasks"], alerts=stats["alerts"],
        max_risk_task=(_task_out(db, stats["max_risk_task"], names.get(stats["max_risk_task"].file_id))
                       if stats["max_risk_task"] else None),
        recent_tasks=[_task_out(db, t, names.get(t.file_id)) for t in stats["recent_tasks"]],
    )


@router.post("", response_model=TaskOut)
def create_task(body: AnalysisCreate, db: Session = Depends(get_db),
                user=Depends(get_current_user)):
    task = task_service.create_task(
        db, file_id=body.file_id, user_id=user.id, username=user.username,
        strategy_ids=body.strategy_ids, severity_threshold=body.severity_threshold,
        time_range=body.time_range, name=body.name)
    db.commit()                      # 先提交再入队：工作线程必须读到已提交的 queued 行
    task_service.enqueue(task.id)
    return _task_out(db, task)


@router.get("", response_model=Page)
def list_tasks(page: int = _PAGE, page_size: int = _PAGE_SIZE, status: str = "",
               file_id: str = "", db: Session = Depends(get_db),
               user=Depends(get_current_user)):
    rows, total = task_service.list_tasks(db, page, page_size, status, file_id)
    names = _file_names(db, rows)
    return Page(total=total, items=[_task_out(db, r, names.get(r.file_id)) for r in rows],
                page=page, page_size=page_size)


@router.get("/{task_id}", response_model=TaskOut)
def get_task(task_id: str, db: Session = Depends(get_db),
             user=Depends(get_current_user)):
    return _task_out(db, task_service.get_task(db, task_id))


@router.post("/{task_id}/cancel", response_model=TaskOut)
def cancel_task(task_id: str, db: Session = Depends(get_db),
                user=Depends(get_current_user)):
    task = task_service.cancel(db, task_id, username=user.username)
    db.commit()
    return _task_out(db, task)


@router.post("/{task_id}/retry", response_model=TaskOut)
def retry_task(task_id: str, db: Session = Depends(get_db),
               user=Depends(get_current_user)):
    task = task_service.retry(db, task_id, username=user.username)
    db.commit()                      # 先提交再入队
    task_service.enqueue(task.id)
    return _task_out(db, task)


# ---------------------------------------------------------------- 回收站
@router.delete("/{task_id}", response_model=TaskOut)
def trash_task(task_id: str, db: Session = Depends(get_db),
               user=Depends(get_current_user)):
    """删除分析任务：移入回收站（可还原）。"""
    task = task_service.trash(db, task_id, username=user.username)
    db.commit()
    return _task_out(db, task)


@router.post("/{task_id}/restore", response_model=TaskOut)
def restore_task(task_id: str, db: Session = Depends(get_db),
                 user=Depends(get_current_user)):
    """从回收站还原任务。"""
    task = task_service.restore(db, task_id, username=user.username)
    db.commit()
    return _task_out(db, task)


@router.delete("/{task_id}/purge")
def purge_task(task_id: str, db: Session = Depends(get_db),
               user=Depends(get_current_user)):
    """彻底删除任务及其全部分析结果。"""
    task_service.purge(db, task_id, username=user.username)
    db.commit()
    return {"deleted": task_id}


@router.get("/{task_id}/summary", response_model=SummaryOut)
def task_summary(task_id: str, db: Session = Depends(get_db),
                 user=Depends(get_current_user)):
    task = task_service.get_task(db, task_id)
    return SummaryOut(task=_task_out(db, task), **queries.task_summary(db, task_id))


@router.get("/{task_id}/alerts", response_model=Page)
def list_alerts(task_id: str, page: int = _PAGE, page_size: int = _PAGE_SIZE,
                severity: str = "", strategy_id: str = "", status: str = "",
                src_ip: str = "", dst_ip: str = "", protocol: str = "", q: str = "",
                db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows, total = queries.list_alerts(db, task_id, page, page_size, severity, strategy_id,
                                      status, src_ip, dst_ip, protocol, q)
    return Page(total=total, items=[queries.alert_to_dict(r) for r in rows],
                page=page, page_size=page_size)


@router.get("/{task_id}/alerts/{alert_id}", response_model=AlertOut)
def get_alert(task_id: str, alert_id: int, db: Session = Depends(get_db),
              user=Depends(get_current_user)):
    a = queries.get_alert(db, task_id, alert_id)
    # 单条告警详情附带结构化证据（alert_evidence 表），列表页不加载避免 N+1
    return queries.alert_to_dict(a, queries.get_alert_evidence(db, alert_id))


@router.post("/{task_id}/alerts/{alert_id}/mark", response_model=AlertOut)
def mark_alert(task_id: str, alert_id: int, body: AlertMarkRequest,
               request: Request, db: Session = Depends(get_db),
               user=Depends(get_current_user)):
    from datetime import datetime, timezone
    a = queries.get_alert(db, task_id, alert_id)
    a.status = body.status
    a.marked_by = user.id
    a.marked_at = datetime.now(timezone.utc)
    a.marked_note = body.note
    audit.log_audit(db, user_id=user.id, username=user.username, action="alert.mark",
                    target_type="alert", target_id=str(alert_id),
                    detail={"status": body.status, "note": body.note}, ip=client_ip(request))
    db.commit()
    return queries.alert_to_dict(a)


@router.get("/{task_id}/sessions", response_model=Page)
def list_sessions(task_id: str, page: int = _PAGE, page_size: int = _PAGE_SIZE,
                  src_ip: str = "", dst_ip: str = "", protocol: str = "",
                  order_by: str = "byte_count", db: Session = Depends(get_db),
                  user=Depends(get_current_user)):
    rows, total = queries.list_sessions(db, task_id, page, page_size, src_ip, dst_ip,
                                        protocol, order_by)
    return Page(total=total, items=[queries.session_to_dict(r) for r in rows],
                page=page, page_size=page_size)


@router.get("/{task_id}/packets", response_model=Page)
def list_packets(task_id: str, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500),
                 frame_number: Optional[int] = None, src_ip: str = "", dst_ip: str = "",
                 protocol: str = "", src_port: Optional[int] = None,
                 dst_port: Optional[int] = None, start_ts: Optional[float] = None,
                 end_ts: Optional[float] = None, db: Session = Depends(get_db),
                 user=Depends(get_current_user)):
    rows, total = queries.list_packets(db, task_id, page, page_size, frame_number, src_ip,
                                       dst_ip, protocol, src_port, dst_port, start_ts, end_ts)
    items = [PacketOut(**queries.packet_to_dict(r)) for r in rows]
    return Page(total=total, items=items, page=page, page_size=page_size)


@router.get("/{task_id}/packets/{frame_number}", response_model=PacketOut)
def get_packet(task_id: str, frame_number: int, db: Session = Depends(get_db),
               user=Depends(get_current_user)):
    p = queries.get_packet(db, task_id, frame_number)
    return PacketOut(**queries.packet_to_dict(p))


@router.get("/{task_id}/report")
def report(task_id: str, format: str = Query("json", pattern="^(json|csv|html|packets_csv)$"),
           db: Session = Depends(get_db), user=Depends(get_current_user)):
    task_service.get_task(db, task_id)
    audit.log_audit(db, user_id=user.id, username=user.username, action="report.export",
                    target_type="analysis_task", target_id=task_id, detail={"format": format})
    db.commit()
    if format == "json":
        return reports.export_json(db, task_id)
    if format == "csv":
        return PlainTextResponse(reports.export_alerts_csv(db, task_id),
                                 media_type="text/csv; charset=utf-8")
    if format == "packets_csv":
        return PlainTextResponse(reports.export_packets_csv(db, task_id),
                                 media_type="text/csv; charset=utf-8")
    return HTMLResponse(reports.export_html(db, task_id))
