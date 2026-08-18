"""边界与状态竞争回归测试（P2-8 / P1-3 / P1-4 / P2-7 等）。"""
import uuid

from tests.fixtures import gen


def _upload(client, path, name=None):
    with open(path, "rb") as fh:
        return client.post("/api/v1/files", files={"file": (name or path.rsplit("/", 1)[-1], fh)})


class TestBoundaryValidation:
    def test_page_params_422(self, client):
        assert client.get("/api/v1/analysis?page=0").status_code == 422
        assert client.get("/api/v1/analysis?page_size=5000").status_code == 422
        assert client.get("/api/v1/files?page=0").status_code == 422
        assert client.get("/api/v1/strategies?page_size=0").status_code == 422
        assert client.get("/api/v1/audit?page=-1").status_code == 422

    def test_invalid_severity_threshold_422(self, client):
        r = client.post("/api/v1/analysis",
                        json={"file_id": "nope", "severity_threshold": "extreme"})
        assert r.status_code == 422

    def test_invalid_time_range_422(self, client):
        r = client.post("/api/v1/analysis", json={"file_id": "nope", "time_range": [100, 50]})
        assert r.status_code == 422
        r = client.post("/api/v1/analysis", json={"file_id": "nope", "time_range": [1, 2, 3]})
        assert r.status_code == 422
        r = client.post("/api/v1/analysis",
                        json={"file_id": "nope", "time_range": ["a", "b"]})
        assert r.status_code == 422

    def test_invalid_alert_mark_status_422(self, client):
        r = client.post("/api/v1/analysis/nope/alerts/1/mark",
                        json={"status": "run", "note": ""})
        assert r.status_code in (404, 422)  # 先校验任务存在，再校验状态；两者都不得 200

    def test_import_invalid_mode_422(self, client):
        r = client.post("/api/v1/strategies/import", json={"items": [], "mode": "merge"})
        assert r.status_code == 422


class TestDashboardStats:
    def test_stats_endpoint_shape(self, client, auth, tmp_path):
        r = client.get("/api/v1/analysis/stats")
        assert r.status_code == 200
        body = r.json()
        for key in ("files", "tasks", "alerts", "max_risk_task", "recent_tasks"):
            assert key in body, body
        assert isinstance(body["files"], int) and body["files"] >= 0

    def test_alert_total_is_global(self, client, auth, tmp_path):
        """仪表盘告警总数来自全库聚合，而不是"最近一页任务"之和（回归：曾只算最近 6 条）。"""
        from app.db import db_session
        from app.services import strategies as svc
        from app.services.tasks import task_service
        # 直接造 2 个成功任务（各 1 条告警），不依赖网络文件
        content = {
            "id": "test.stats_rule", "name": "统计规则", "version": "1.0.0",
            "category": "test", "scope": "packet", "severity": "info",
            "weight": 10, "confidence": 0.5,
            "conditions": {"field": "ip.src", "op": "eq", "value": "10.0.0.5"},
        }
        with db_session() as s:
            svc.create_strategy(s, content, username="t")
            svc.publish_version(s, "test.stats_rule", username="t")
            svc.set_enabled(s, "test.stats_rule", True)
            p = tmp_path / "s.pcapng"
            gen.make_scan_pcap(str(p), n_ports=3)
            from app.services.files import save_upload
            with open(p, "rb") as fh:
                f, _ = save_upload(s, fh, "s.pcapng", None, "t")
            task = task_service.create_task(s, file_id=f.id, user_id=None, username="t",
                                            strategy_ids=["test.stats_rule"])
            s.commit()
            task_service.enqueue(task.id)
        from tests.conftest import wait_task
        finished = wait_task(client, {}, task.id, timeout=60)
        assert finished["status"] == "succeeded"
        assert finished["alert_count"] >= 1
        r = client.get("/api/v1/analysis/stats")
        assert r.json()["alerts"] >= finished["alert_count"]


class TestStrategySnapshot:
    def test_21_enabled_strategies_all_in_snapshot(self, client):
        """默认任务必须加载全部启用策略（回归：分页查询曾只取前 20 条）。"""
        from app.db import db_session
        from app.services import strategies as svc
        from app.services.tasks import task_service
        from app.services.files import save_upload
        from tests.fixtures import gen
        import tempfile, os
        n = 21
        with db_session() as s:
            for i in range(n):
                sid = f"test.all_{i}"
                content = {
                    "id": sid, "name": f"策略 {i}", "version": "1.0.0",
                    "category": "test", "scope": "packet", "severity": "info",
                    "weight": 1, "confidence": 0.5,
                    "conditions": {"field": "ip.src", "op": "eq", "value": "10.77.0.1"},
                }
                svc.create_strategy(s, content, username="t")
                svc.publish_version(s, sid, username="t")
                svc.set_enabled(s, sid, True)
            p = tempfile.mktemp(suffix=".pcapng")
            gen.make_normal_pcap(p)
            with open(p, "rb") as fh:
                f, _ = save_upload(s, fh, "n.pcapng", None, "t")
            task = task_service.create_task(s, file_id=f.id, user_id=None, username="t")
            # 21 条新启用策略全部进入快照（加上内置策略总量 > 20），不再被第一页 20 条截断
            assert len(task.strategy_set) >= n, len(task.strategy_set)
            snap_ids = {item["id"] for item in task.strategy_set}
            assert {f"test.all_{i}" for i in range(n)} <= snap_ids
            # 快照带 version_id，工作线程一次查询即可全部加载
            assert all("version_id" in item for item in task.strategy_set)
            os.unlink(p)

    def test_disabled_strategy_not_in_default_snapshot(self, client):
        from app.db import db_session
        from app.services import strategies as svc
        from app.services.tasks import task_service
        from app.services.files import save_upload
        from tests.fixtures import gen
        import tempfile, os
        with db_session() as s:
            content = {
                "id": "test.disabled_one", "name": "停用策略", "version": "1.0.0",
                "category": "test", "scope": "packet", "severity": "info",
                "weight": 1, "confidence": 0.5,
                "conditions": {"field": "ip.src", "op": "eq", "value": "10.66.0.1"},
            }
            svc.create_strategy(s, content, username="t")
            svc.publish_version(s, "test.disabled_one", username="t")
            # 不启用
            p = tempfile.mktemp(suffix=".pcapng")
            gen.make_normal_pcap(p)
            with open(p, "rb") as fh:
                f, _ = save_upload(s, fh, "n.pcapng", None, "t")
            task = task_service.create_task(s, file_id=f.id, user_id=None, username="t")
            assert all(item["id"] != "test.disabled_one" for item in task.strategy_set)
            os.unlink(p)

    def test_custom_strategy_enabled_in_content_executes(self, client):
        """内容 enabled: false 但数据库已启用的策略必须执行（回归：引擎曾按内容 enabled 静默跳过）。"""
        from app.db import db_session
        from app.services import strategies as svc
        from app.services.tasks import task_service
        from app.services.files import save_upload
        from tests.fixtures import gen
        import tempfile, os
        content = {
            "id": "test.content_enabled_false", "name": "内容停用但已启用", "version": "1.0.0",
            "category": "test", "scope": "packet", "enabled": False, "severity": "low",
            "weight": 20, "confidence": 1.0,
            "conditions": {"field": "ip.src", "op": "eq", "value": "10.0.0.5"},
        }
        with db_session() as s:
            svc.create_strategy(s, content, username="t")
            svc.publish_version(s, "test.content_enabled_false", username="t")
            svc.set_enabled(s, "test.content_enabled_false", True)  # 数据库启用
            p = tempfile.mktemp(suffix=".pcapng")
            gen.make_normal_pcap(p)
            with open(p, "rb") as fh:
                f, _ = save_upload(s, fh, "n.pcapng", None, "t")
            task = task_service.create_task(s, file_id=f.id, user_id=None, username="t",
                                            strategy_ids=["test.content_enabled_false"])
            s.commit()
            task_service.enqueue(task.id)
            os.unlink(p)
        from tests.conftest import wait_task
        finished = wait_task(client, {}, task.id, timeout=60)
        assert finished["status"] == "succeeded"
        assert finished["alert_count"] >= 1


class TestTrashRestoreStateMachine:
    def _mk_file(self, client, tmp_path):
        p = tmp_path / "n.pcapng"
        gen.make_normal_pcap(str(p))
        r = _upload(client, str(p))
        return r.json()["id"]

    def test_restore_queued_task_becomes_cancelled(self, client, tmp_path):
        """回收站还原活动快照：不得恢复为 queued（会永久卡住），应恢复为 cancelled。"""
        from app.db import db_session
        from app.services.tasks import task_service
        fid = self._mk_file(client, tmp_path)
        with db_session() as s:
            task = task_service.create_task(s, file_id=fid, user_id=None, username="t")
            tid = task.id
            s.commit()
            # 移入回收站（不提交入队），再还原
            task_service.trash(s, tid)
            s.flush()
            restored = task_service.restore(s, tid)
            assert restored.status == "cancelled"
            assert "重试" in restored.error_message
            s.rollback()

    def test_restore_running_task_becomes_cancelled(self, client, tmp_path):
        from app.db import db_session
        from app.services.tasks import task_service
        fid = self._mk_file(client, tmp_path)
        with db_session() as s:
            task = task_service.create_task(s, file_id=fid, user_id=None, username="t")
            tid = task.id
            task.status = "running"
            s.commit()
            task_service.trash(s, tid)
            s.flush()
            restored = task_service.restore(s, tid)
            assert restored.status == "cancelled"
            s.rollback()

    def test_restore_succeeded_preserves_finished_at(self, client, tmp_path):
        """成功任务还原：恢复为 succeeded，finished_at 不再被删除时间覆盖。"""
        from datetime import datetime, timezone
        from app.db import db_session
        from app.services.tasks import task_service
        fid = self._mk_file(client, tmp_path)
        with db_session() as s:
            task = task_service.create_task(s, file_id=fid, user_id=None, username="t")
            tid = task.id
            task.status = "succeeded"
            task.finished_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
            s.commit()
            task_service.trash(s, tid)
            s.flush()
            assert task.deleted_at is not None
            restored = task_service.restore(s, tid)
            assert restored.status == "succeeded"
            assert restored.finished_at.year == 2020   # 真实完成时间保留
            assert restored.deleted_at is None
            s.rollback()


class TestStartupRecovery:
    def test_stale_tasks_marked_failed(self, client, tmp_path):
        """服务重启后 queued/running 任务被标记 failed（进程内队列已丢失，用户显式重试）。"""
        from app.db import db_session
        from app.services.tasks import task_service
        from app.models import AnalysisTask
        p = tmp_path / "n.pcapng"
        gen.make_normal_pcap(str(p))
        r = _upload(client, str(p))
        fid = r.json()["id"]
        with db_session() as s:
            for status in ("queued", "running"):
                t = AnalysisTask(id=uuid.uuid4().hex, file_id=fid, status=status,
                                 strategy_set=[], created_by_name="t", progress=0, stage=status)
                s.add(t)
            s.flush()
            n = task_service.recover_stale_tasks(s)
            assert n >= 2
            assert s.query(AnalysisTask).filter(
                AnalysisTask.status.in_(["queued", "running"])).count() == 0
            failed = s.query(AnalysisTask).filter(AnalysisTask.status == "failed").all()
            assert len(failed) >= 2
            assert all(t.error_message for t in failed)
