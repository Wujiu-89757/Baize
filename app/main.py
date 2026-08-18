"""白泽流量分析平台 v0.1 —— FastAPI 入口（本地免登录模式）。

启动：uvicorn app.main:app --host 127.0.0.1 --port 8000
首次启动自动：初始化数据库、导入并发布内置策略、恢复上次遗留的活动任务。
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api import analysis, audit, files, strategies
from app.core.config import settings
from app.core.errors import AppError, error_body
from app.core.logging import get_logger, request_id_var, setup_logging
from app.db import db_session, init_db
from app.services import strategies as strategy_service
from app.services.tasks import task_service

log = get_logger("baize.main")

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _bootstrap() -> None:
    init_db()
    with db_session() as session:
        # 内置策略：缺失导入、自动发布、启用
        result = strategy_service.seed_builtin(session)
        log.info("builtin strategies seeded",
                 extra={"extra_fields": {"created": result["created"], "skipped": result["skipped"]}})
        # 重启恢复：进程内队列已丢失，遗留活动任务标记为失败（用户显式重试）
        recovered = task_service.recover_stale_tasks(session)
        if recovered:
            log.warning("stale tasks recovered", extra={"extra_fields": {"count": recovered}})


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging(settings.debug)
    _bootstrap()
    yield
    task_service.executor.shutdown(wait=False, cancel_futures=True)


app = FastAPI(
    title="白泽流量分析平台",
    description="基于 PCAP/PCAPNG 的恶意流量分析平台 v0.1：上传管理、策略库、异步分析、"
                "可解释告警与证据、报告导出。本地免登录模式。详见 OpenAPI 文档与前端页面。",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    rid = request.headers.get("X-Request-Id") or uuid.uuid4().hex[:16]
    token = request_id_var.set(rid)
    try:
        response = await call_next(request)
    finally:
        request_id_var.reset(token)
    response.headers["X-Request-Id"] = rid
    return response


@app.exception_handler(AppError)
async def app_error_handler(request: Request, exc: AppError):
    return JSONResponse(status_code=exc.status_code,
                        content=error_body(exc, request_id_var.get()))


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    log.exception("unhandled error", extra={"extra_fields": {"path": request.url.path}})
    # 客户端不返回内部异常文本，避免泄露堆栈/路径（调试模式除外）
    detail = str(exc) if settings.debug else "请查看服务端日志"
    return JSONResponse(status_code=500, content={
        "code": "internal_error", "message": "服务器内部错误", "detail": detail,
        "request_id": request_id_var.get()})


@app.get("/api/v1/meta")
def meta():
    return {"app": settings.app_name, "version": __version__,
            "engine_version": settings.engine_version}


app.include_router(files.router)
app.include_router(strategies.router)
app.include_router(analysis.router)
app.include_router(audit.router)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
