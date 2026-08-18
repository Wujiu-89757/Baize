"""分析任务服务（文档 8.1/8.6）：队列调度、进度、取消、重试、结果查询。"""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import insert
from sqlalchemy.orm import Session

from app.analysis.engine import TaskCancelled, run_analysis
from app.core.config import settings
from app.core.errors import NotFoundError, TaskStateError, ValidationError
from app.core.logging import get_logger, task_id_var
from app.db import db_session
from app.models import Alert, AlertEvidence, AnalysisTask, Packet, Session as FlowSession, StrategyVersion, UploadedFile
from app.services import strategies as strategy_service
from app.services import audit

log = get_logger("baize.tasks")

_CHUNK = 2000


class TaskService:
    def __init__(self) -> None:
        self.executor = ThreadPoolExecutor(max_workers=settings.worker_concurrency,
                                           thread_name_prefix="baize-worker")

    # ------------------------------------------------------------ 创建/入队
    def create_task(self, session: Session, *, file_id: str, user_id: Optional[int],
                    username: str, strategy_ids: Optional[list[str]] = None,
                    severity_threshold: Optional[str] = None,
                    time_range: Optional[list[float]] = None,
                    name: Optional[str] = None) -> AnalysisTask:
        from app.services.files import get_file
        f = get_file(session, file_id)
        if f.status == "invalid":
            raise ValidationError("文件无效，无法分析")

        # 一次性取得全部启用策略及其当前发布版本（默认任务不再只取第一页，也不再有 N+1）
        snapshot: list[dict] = []
        if strategy_ids:
            published = strategy_service.get_published_versions(session, strategy_ids)
            for sid in strategy_ids:
                v = published.get(sid)
                if v is None:
                    raise NotFoundError(f"策略 {sid} 没有已发布版本")
                snapshot.append({"id": sid, "version": v.version, "version_id": v.id})
        else:
            for strat, ver in strategy_service.list_enabled_published_versions(session):
                snapshot.append({"id": strat.id, "version": ver.version, "version_id": ver.id})
        if not snapshot:
            raise ValidationError("没有可用的已发布策略，请先发布并启用策略")

        task = AnalysisTask(
            id=uuid.uuid4().hex, file_id=file_id, file_sha256=f.sha256,
            strategy_set=snapshot, status="queued", progress=0, stage="queued",
            created_by=user_id, created_by_name=username or "-",
            engine_version=settings.engine_version,
            config_snapshot={"severity_multipliers": settings.severity_multipliers,
                             "score_cap": settings.score_normalization_cap,
                             "strategy_score_cap": settings.per_strategy_score_cap,
                             "severity_threshold": severity_threshold,
                             "time_range": time_range, "name": name},
        )
        session.add(task)
        session.flush()
        audit.log_audit(session, user_id=user_id, username=username, action="task.create",
                        target_type="analysis_task", target_id=task.id,
                        detail={"file_id": file_id, "strategies": snapshot})
        session.flush()
        return task

    def enqueue(self, task_id: str) -> None:
        """入队执行。必须在事务提交之后调用：工作线程读取已提交的行，
        否则 SQLite 下要么读到旧快照（任务永远 queued）要么锁冲突。"""
        self.executor.submit(self._run_task, task_id)

    # ------------------------------------------------------------ 工作线程
    def _run_task(self, task_id: str) -> None:
        task_id_var.set(task_id)
        try:
            with db_session() as session:
                task = session.get(AnalysisTask, task_id)
                if task is None or task.status != "queued":
                    return
                task.status = "running"
                task.started_at = datetime.now(timezone.utc)
                session.commit()

            strategy_contents: list[dict] = []
            file_path = ""
            with db_session() as session:
                task = session.get(AnalysisTask, task_id)
                f = session.get(UploadedFile, task.file_id)
                if f is None:
                    raise NotFoundError("文件不存在")
                file_path = f.storage_path
                # 一次查询加载全部版本内容，避免逐条 N+1
                vids = [item.get("version_id") for item in task.strategy_set if item.get("version_id")]
                content_by_id: dict[int, dict] = {}
                if vids:
                    rows = session.query(StrategyVersion).filter(StrategyVersion.id.in_(vids)).all()
                    content_by_id = {v.id: v.content for v in rows}
                for item in task.strategy_set:
                    content = content_by_id.get(item.get("version_id"))
                    if content is None and item.get("version") is not None:
                        # 兼容旧快照（无 version_id）：按版本号回退查询
                        ver = strategy_service.get_version(session, item["id"], item["version"])
                        content = ver.content
                    if content is not None:
                        strategy_contents.append(content)

            last = [0, ""]

            def progress_cb(pct: int, stage: str) -> None:
                if pct - last[0] < 1 and stage == last[1]:
                    return
                last[0] = pct
                last[1] = stage
                try:
                    with db_session() as s:
                        t = s.get(AnalysisTask, task_id)
                        if t is None:
                            return
                        t.progress = min(100, pct)
                        t.stage = stage
                        s.commit()
                except Exception:  # noqa: BLE001
                    pass

            def cancel_check() -> bool:
                try:
                    with db_session() as s:
                        t = s.get(AnalysisTask, task_id)
                        return bool(t and t.cancel_requested)
                except Exception:  # noqa: BLE001
                    return False

            result = run_analysis(
                file_path, strategy_contents,
                progress_cb=progress_cb,
                cancel_check=cancel_check,
                time_range=task.config_snapshot.get("time_range"),
                severity_threshold=task.config_snapshot.get("severity_threshold"),
            )
            self._persist(task_id, result)
        except TaskCancelled:
            self._finish(task_id, status="cancelled", error="任务已被取消")
        except Exception as exc:  # noqa: BLE001
            log.exception("task failed", extra={"extra_fields": {"task_id": task_id, "error": str(exc)}})
            self._finish(task_id, status="failed", error=str(exc))

    def _check_cancel_db(self, session: Session, task_id: str) -> None:
        fresh = (session.query(AnalysisTask.cancel_requested)
                 .filter(AnalysisTask.id == task_id).scalar())
        if fresh:
            raise TaskCancelled("任务已被取消")

    def _persist(self, task_id: str, result: dict) -> None:
        with db_session() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None or task.status == "deleted":
                raise TaskCancelled("任务已被移入回收站，分析结果丢弃")
            summary = result["summary"]

            # Core insert 分批写包/会话，不驻留 ORM identity map（降低大文件内存占用）
            packets = result["packets"]
            for i in range(0, len(packets), _CHUNK):
                chunk = packets[i:i + _CHUNK]
                for row in chunk:
                    row["task_id"] = task_id
                session.execute(insert(Packet), chunk)
                self._check_cancel_db(session, task_id)

            session_rows = result["sessions"]
            for i in range(0, len(session_rows), _CHUNK):
                chunk = session_rows[i:i + _CHUNK]
                for row in chunk:
                    row["task_id"] = task_id
                session.execute(insert(FlowSession), chunk)
                self._check_cancel_db(session, task_id)

            alert_ids: list[int] = []
            for row in result["alerts"]:
                alert = Alert(task_id=task_id,
                              **{k: v for k, v in row.items()
                                 if k not in ("_evidence", "_dedup_key", "task_id")})
                session.add(alert)
                session.flush()
                alert_ids.append(alert.id)
                for ev in row.get("_evidence", []):
                    session.add(AlertEvidence(task_id=task_id, alert_id=alert.id,
                                              **{k: v for k, v in ev.items()
                                                 if k not in ("task_id", "alert_id")}))

            task.status = "succeeded"
            task.progress = 100
            task.stage = "完成"
            task.finished_at = datetime.now(timezone.utc)
            task.risk_score = summary.get("risk_score", 0.0)
            task.risk_level = summary.get("risk_level", "info")
            task.alert_count = len(result["alerts"])
            task.strategy_hits = len(result["alerts"])
            task.parse_summary = summary.get("parse_stats", {})
            session.commit()
            log.info("task succeeded", extra={
                "extra_fields": {"task_id": task_id, "alerts": len(result["alerts"]),
                                 "packets": summary.get("parse_stats", {}).get("packets"),
                                 "risk": task.risk_level}})

    def _finish(self, task_id: str, status: str, error: str = "") -> None:
        with db_session() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None or task.status == "deleted":
                return  # 任务已被移入回收站，保持回收站状态
            task.status = status
            task.finished_at = datetime.now(timezone.utc)
            task.stage = {"failed": "失败", "cancelled": "已取消"}.get(status, status)
            task.error_message = error[:2000]
            session.commit()

    # ------------------------------------------------------------ 查询
    def get_task(self, session: Session, task_id: str) -> AnalysisTask:
        task = session.get(AnalysisTask, task_id)
        if task is None:
            raise NotFoundError(f"任务不存在: {task_id}")
        return task

    def list_tasks(self, session: Session, page: int = 1, page_size: int = 20,
                   status: str = "", file_id: str = "") -> tuple[list[AnalysisTask], int]:
        q = session.query(AnalysisTask)
        if status:
            # 回收站：status=deleted 等显式状态
            q = q.filter(AnalysisTask.status == status)
        else:
            # 常规列表：排除已删除（回收站）任务
            q = q.filter(AnalysisTask.status != "deleted")
        if file_id:
            q = q.filter(AnalysisTask.file_id == file_id)
        total = q.count()
        rows = q.order_by(AnalysisTask.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
        return rows, total

    def cancel(self, session: Session, task_id: str, username: str = "") -> AnalysisTask:
        task = self.get_task(session, task_id)
        if task.status == "deleted":
            raise TaskStateError("任务已在回收站，请先还原")
        if task.status in ("succeeded", "failed", "cancelled"):
            raise TaskStateError(f"任务已处于 {task.status} 状态，无法取消")
        if task.status == "queued":
            task.status = "cancelled"
            task.finished_at = datetime.now(timezone.utc)
            task.stage = "已取消"
        else:
            task.cancel_requested = True
            task.stage = "取消中"
        audit.log_audit(session, user_id=task.created_by, username=username,
                        action="task.cancel", target_type="analysis_task", target_id=task.id)
        session.flush()
        return task

    def retry(self, session: Session, task_id: str, username: str = "") -> AnalysisTask:
        task = self.get_task(session, task_id)
        if task.status == "deleted":
            raise TaskStateError("任务已在回收站，请先还原")
        if task.status == "running":
            raise TaskStateError("任务正在运行，无法重试")
        if task.status == "queued":
            raise TaskStateError("任务已在队列中")
        if task.retry_count >= settings.task_retry_limit:
            raise TaskStateError("已达重试上限")
        task.status = "queued"
        task.progress = 0
        task.stage = "queued"
        task.error_message = ""
        task.cancel_requested = False
        task.retry_count += 1
        task.started_at = None
        task.finished_at = None
        audit.log_audit(session, user_id=task.created_by, username=username,
                        action="task.retry", target_type="analysis_task", target_id=task_id)
        session.flush()
        return task

    # ------------------------------------------------------------ 回收站
    def trash(self, session: Session, task_id: str, username: str = "") -> AnalysisTask:
        """软删除：任务移入回收站（保存原状态，可还原）。"""
        task = self.get_task(session, task_id)
        if task.status == "deleted":
            raise TaskStateError("任务已在回收站")
        snap = dict(task.config_snapshot or {})
        snap["restore_status"] = task.status
        task.config_snapshot = snap
        task.status = "deleted"
        task.cancel_requested = True  # 若仍在运行，工作线程将停止并保持回收站状态
        task.deleted_at = datetime.now(timezone.utc)  # 单独记录回收站时间，不复用 finished_at
        audit.log_audit(session, user_id=task.created_by, username=username,
                        action="task.trash", target_type="analysis_task", target_id=task.id)
        session.flush()
        return task

    def restore(self, session: Session, task_id: str, username: str = "") -> AnalysisTask:
        """从回收站还原任务。

        只有终态（succeeded/failed/cancelled）恢复为原状态；queued/running 等活动快照
        一律恢复为 cancelled，由用户显式重试，绝不恢复为"看似活动却无人执行"的状态。
        """
        task = self.get_task(session, task_id)
        if task.status != "deleted":
            raise TaskStateError("任务不在回收站")
        snap = dict(task.config_snapshot or {})
        restore_status = snap.pop("restore_status", "succeeded")
        if restore_status in ("queued", "running"):
            task.status = "cancelled"
            task.stage = "已取消"
            task.error_message = f"任务被删除时处于 {restore_status} 状态，还原后已取消，请点击重试"
            task.finished_at = datetime.now(timezone.utc)
        else:
            if restore_status == "deleted":
                restore_status = "succeeded"
            task.status = restore_status
        task.config_snapshot = snap
        task.deleted_at = None
        task.cancel_requested = False
        audit.log_audit(session, user_id=task.created_by, username=username,
                        action="task.restore", target_type="analysis_task", target_id=task.id)
        session.flush()
        return task

    def purge(self, session: Session, task_id: str, username: str = "") -> None:
        """彻底删除：任务及其全部分析结果（包/会话/告警/证据）。"""
        task = self.get_task(session, task_id)
        if task.status != "deleted":
            raise TaskStateError("只能彻底删除回收站中的任务")
        session.query(AlertEvidence).filter(AlertEvidence.task_id == task_id).delete()
        session.query(Alert).filter(Alert.task_id == task_id).delete()
        session.query(Packet).filter(Packet.task_id == task_id).delete()
        session.query(FlowSession).filter(FlowSession.task_id == task_id).delete()
        session.delete(task)
        audit.log_audit(session, user_id=task.created_by, username=username,
                        action="task.purge", target_type="analysis_task", target_id=task_id)
        session.flush()

    # ------------------------------------------------------------ 重启恢复
    def recover_stale_tasks(self, session: Session) -> int:
        """应用启动恢复：进程内线程池队列已丢失，遗留 queued/running 任务一律标记 failed。"""
        stale = session.query(AnalysisTask).filter(
            AnalysisTask.status.in_(["queued", "running"])).all()
        for t in stale:
            t.status = "failed"
            t.stage = "失败"
            t.error_message = "服务重启导致任务中断，请点击重试"
            t.finished_at = datetime.now(timezone.utc)
            t.cancel_requested = False
        if stale:
            session.flush()
        return len(stale)


task_service = TaskService()
