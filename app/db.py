"""数据库会话管理。SQLite 演示库；PostgreSQL 可通过 BAIZE_DB_URL 切换。"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.models import Base

_kwargs = {"pool_pre_ping": True}
if settings.db_url.startswith("sqlite"):
    # 多线程（API 线程 + 分析工作线程）访问 SQLite：
    # - timeout=30：锁竞争时等待而非立即报 "database is locked"；
    # - WAL 模式：读不阻塞写、写不阻塞读，避免进度/取消检查与持久化写事务互相阻塞。
    _kwargs.update({"connect_args": {"check_same_thread": False, "timeout": 30},
                    "pool_pre_ping": False})

engine = create_engine(settings.db_url, **_kwargs)


if settings.db_url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, connection_record):  # noqa: ARG001
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _migrate_sqlite()


def _migrate_sqlite() -> None:
    """SQLite 轻量迁移：为已存在的表补充新增列/索引（create_all 不会改已有表）。

    增量改动，不删除任何用户数据：
    - packets：补充 http_body_head / tcp_payload_head 列与 (task_id, frame_number) 复合索引；
    - analysis_tasks：补充 deleted_at 列（回收站时间，不再复用 finished_at）；
    - strategy_versions：补充 (strategy_id, version) 唯一约束，防止并发下重复版本。
    """
    if not settings.db_url.startswith("sqlite"):
        return
    from sqlalchemy import inspect, text

    insp = inspect(engine)
    with engine.begin() as conn:
        # packets 列与索引
        if insp.has_table("packets"):
            cols = {c["name"] for c in insp.get_columns("packets")}
            for col in ("http_body_head", "tcp_payload_head"):
                if col not in cols:
                    conn.execute(text(f"ALTER TABLE packets ADD COLUMN {col} TEXT"))
            idxs = {r["name"] for r in insp.get_indexes("packets")}
            if "ix_packets_task_id_frame_number" not in idxs:
                conn.execute(text(
                    "CREATE INDEX ix_packets_task_id_frame_number ON packets (task_id, frame_number)"))
        # analysis_tasks.deleted_at
        if insp.has_table("analysis_tasks"):
            tcols = {c["name"] for c in insp.get_columns("analysis_tasks")}
            if "deleted_at" not in tcols:
                conn.execute(text("ALTER TABLE analysis_tasks ADD COLUMN deleted_at DATETIME"))
        # strategy_versions 唯一约束（先检查是否已有重复，避免索引创建失败）
        if insp.has_table("strategy_versions"):
            idxs = {r["name"] for r in insp.get_indexes("strategy_versions")}
            if "uq_strategy_versions_strategy_id_version" not in idxs:
                dup = conn.execute(text(
                    "SELECT strategy_id, version FROM strategy_versions "
                    "GROUP BY strategy_id, version HAVING COUNT(*) > 1 LIMIT 1")).fetchone()
                if dup is None:
                    conn.execute(text(
                        "CREATE UNIQUE INDEX uq_strategy_versions_strategy_id_version "
                        "ON strategy_versions (strategy_id, version)"))


def drop_db() -> None:
    Base.metadata.drop_all(bind=engine)


@contextmanager
def db_session() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
