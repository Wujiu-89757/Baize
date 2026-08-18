"""pytest 配置：隔离的临时数据目录 + 应用夹具。"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_TMP = tempfile.mkdtemp(prefix="baize-test-")
os.environ.setdefault("BAIZE_DATA_DIR", os.path.join(_TMP, "data"))
os.environ.setdefault("BAIZE_UPLOAD_DIR", os.path.join(_TMP, "uploads"))
os.environ.setdefault("BAIZE_STORAGE_DIR", os.path.join(_TMP, "storage"))
os.environ.setdefault("BAIZE_REPORT_DIR", os.path.join(_TMP, "reports"))
os.environ.setdefault("BAIZE_DB_URL", f"sqlite:///{os.path.join(_TMP, 'test.db')}")
os.environ.setdefault("BAIZE_SECRET_KEY", "test-secret-key-0123456789abcdef-0123456789")
os.environ.setdefault("BAIZE_DEBUG", "false")
os.environ.setdefault("BAIZE_WORKER_CONCURRENCY", "2")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="session")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def auth(client):
    """本地免登录模式：无鉴权，返回空请求头（保留参数以兼容既有测试签名）。"""
    return {}


def wait_task(client, headers, task_id, timeout=120):
    """轮询任务直至终态。"""
    import time
    t0 = time.time()
    while True:
        r = client.get(f"/api/v1/analysis/{task_id}", headers=headers)
        assert r.status_code == 200
        t = r.json()
        if t["status"] in ("succeeded", "failed", "cancelled"):
            return t
        assert time.time() - t0 < timeout, "task timeout"
        time.sleep(0.5)
