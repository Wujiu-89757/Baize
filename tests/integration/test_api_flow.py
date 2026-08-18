"""集成测试：上传 → 分析 → 告警 → 标记 → 报告（文档 12.4/14 验收）。"""
from tests.conftest import wait_task
from tests.fixtures import gen


def _upload(client, headers, path, name=None):
    with open(path, "rb") as fh:
        r = client.post("/api/v1/files", headers=headers,
                        files={"file": (name or path.rsplit("/", 1)[-1], fh)})
    return r


class TestUpload:
    def test_upload_and_metadata(self, client, auth, tmp_path):
        p = tmp_path / "scan.pcapng"
        gen.make_scan_pcap(str(p), n_ports=50)
        r = _upload(client, auth, str(p))
        assert r.status_code == 200, r.text
        f = r.json()
        assert f["format"] == "pcapng"
        assert len(f["sha256"]) == 64
        assert f["status"] == "uploaded"
        assert f["size_bytes"] == p.stat().st_size

    def test_duplicate_detection(self, client, auth, tmp_path):
        p = tmp_path / "d.pcap"
        gen.make_normal_pcap(str(p))
        r1 = _upload(client, auth, str(p))
        r2 = _upload(client, auth, str(p))
        assert r1.status_code == 200 and r2.status_code == 200
        # 本次上传被去重，但原记录不再被打上 duplicate_of（不污染历史文件）
        assert r2.json()["deduplicated"] is True
        assert r2.json()["duplicate_of"] is None
        assert r2.json()["id"] == r1.json()["id"]
        # 列表去重后只出现一次，且不是"重复"标记记录
        r = client.get("/api/v1/files", headers=auth)
        items = [i for i in r.json()["items"] if i["sha256"] == r1.json()["sha256"]]
        assert len(items) == 1
        assert items[0]["duplicate_of"] is None


class TestAnalysis:
    def _analyze(self, client, auth, tmp_path, strategy_ids=None):
        p = tmp_path / "scan.pcapng"
        gen.make_scan_pcap(str(p), n_ports=150)
        r = _upload(client, auth, str(p))
        assert r.status_code == 200
        fid = r.json()["id"]
        body = {"file_id": fid}
        if strategy_ids:
            body["strategy_ids"] = strategy_ids
        r = client.post("/api/v1/analysis", headers=auth, json=body)
        assert r.status_code == 200, r.text
        task = wait_task(client, auth, r.json()["id"])
        return fid, task

    def test_scan_detection(self, client, auth, tmp_path):
        fid, task = self._analyze(client, auth, tmp_path,
                                  strategy_ids=["scan.tcp_syn_scan"])
        assert task["status"] == "succeeded", task
        # 归一化到 0~100：单策略扫描原始分 ~98 → 49（回归：原来可返回 165 之类 >100 的分）
        assert task["risk_score"] <= 100
        assert task["risk_score"] > 0
        assert task["risk_level"] == "medium"
        assert task["parse_summary"]["packets"] == 8 + 150 * 2

        r = client.get(f"/api/v1/analysis/{task['id']}/alerts", headers=auth)
        alerts = r.json()
        assert alerts["total"] >= 1
        scan = next(a for a in alerts["items"] if a["strategy_id"] == "scan.tcp_syn_scan")
        assert scan["src_ip"] == "10.0.0.1" and scan["dst_ip"] == "10.0.0.2"
        assert scan["severity"] == "high"
        assert scan["stats"]["syn_count"] == 150
        assert scan["stats"]["distinct_dst_ports"] == 150
        assert scan["stats"]["pure_syn_ratio"] == 1.0
        # 命中字段证据与代表帧
        assert any(h["field"] == "session.syn_count" for h in scan["hit_fields"])
        assert len(scan["evidence_packets"]) >= 1

        # 包上下文（文档 8.6：包详情）
        frame = scan["evidence_packets"][0]
        r = client.get(f"/api/v1/analysis/{task['id']}/packets/{frame}", headers=auth)
        assert r.status_code == 200
        pkt = r.json()
        assert pkt["src_ip"] == "10.0.0.1"
        assert pkt["tcp_syn"] is True

        # 会话列表
        r = client.get(f"/api/v1/analysis/{task['id']}/sessions?page_size=5", headers=auth)
        assert r.status_code == 200 and r.json()["total"] > 0

    def test_beacon_detection(self, client, auth, tmp_path):
        p = tmp_path / "b.pcap"
        gen.make_beacon_pcap(str(p))
        r = _upload(client, auth, str(p))
        fid = r.json()["id"]
        r = client.post("/api/v1/analysis", headers=auth,
                        json={"file_id": fid, "strategy_ids": ["outbound.beacon_periodicity"]})
        task = wait_task(client, auth, r.json()["id"])
        assert task["status"] == "succeeded", task
        r = client.get(f"/api/v1/analysis/{task['id']}/alerts", headers=auth)
        assert r.json()["total"] >= 1
        beacon = r.json()["items"][0]
        assert beacon["strategy_id"] == "outbound.beacon_periodicity"
        assert beacon["dst_port"] == 4444
        # 分组是方向性的：发起方向 8 个包（回包方向为另一个分组）
        assert beacon["stats"]["packet_count"] == 8

    def test_normal_traffic_no_scan_alert(self, client, auth, tmp_path):
        p = tmp_path / "n.pcap"
        gen.make_normal_pcap(str(p))
        r = _upload(client, auth, str(p))
        fid = r.json()["id"]
        r = client.post("/api/v1/analysis", headers=auth,
                        json={"file_id": fid, "strategy_ids": ["scan.tcp_syn_scan"]})
        task = wait_task(client, auth, r.json()["id"])
        assert task["status"] == "succeeded"
        r = client.get(f"/api/v1/analysis/{task['id']}/alerts", headers=auth)
        assert r.json()["total"] == 0
        assert task["risk_level"] == "info"

    def test_alert_evidence_persisted(self, client, auth, tmp_path):
        """回归：alert_evidence 必须真正落库并关联到正确告警（原实现引擎剥离证据后从未写入）。"""
        fid, task = self._analyze(client, auth, tmp_path,
                                  strategy_ids=["scan.tcp_syn_scan"])
        r = client.get(f"/api/v1/analysis/{task['id']}/alerts", headers=auth)
        assert r.status_code == 200
        scan = [a for a in r.json()["items"] if a["strategy_id"] == "scan.tcp_syn_scan"]
        assert scan
        from app.db import db_session
        from app.models import AlertEvidence
        with db_session() as s:
            rows = s.query(AlertEvidence).filter(AlertEvidence.task_id == task["id"]).all()
            assert rows, "alert_evidence 未落库"
            alert_ids = {a["id"] for a in r.json()["items"]}
            ev_alert_ids = {e.alert_id for e in rows}
            assert ev_alert_ids and ev_alert_ids <= alert_ids, "证据未关联到任务内告警"
            # 每个告警的命中条件都应有一条证据（字段/实际值/期望/算子）
            scan_alert = next(a for a in scan)
            ev_for_scan = [e for e in rows if e.alert_id == scan_alert["id"]]
            assert len(ev_for_scan) == len(scan_alert["hit_fields"])
            assert ev_for_scan[0].frame_number == scan_alert["evidence_packets"][0]
        # 单条告警详情接口暴露结构化证据
        r = client.get(f"/api/v1/analysis/{task['id']}/alerts/{scan[0]['id']}", headers=auth)
        detail = r.json()
        assert len(detail["evidence"]) == len(scan[0]["hit_fields"])
        assert detail["evidence"][0]["field"] == scan[0]["hit_fields"][0]["field"]

    def test_mark_alert(self, client, auth, tmp_path):
        fid, task = self._analyze(client, auth, tmp_path,
                                  strategy_ids=["scan.tcp_syn_scan"])
        r = client.get(f"/api/v1/analysis/{task['id']}/alerts", headers=auth)
        alert_id = r.json()["items"][0]["id"]
        r = client.post(f"/api/v1/analysis/{task['id']}/alerts/{alert_id}/mark",
                        headers=auth, json={"status": "confirmed", "note": "内网授权扫描"})
        assert r.status_code == 200
        assert r.json()["status"] == "confirmed"
        assert r.json()["marked_note"] == "内网授权扫描"


class TestReports:
    def _succeeded_task(self, client, auth, tmp_path):
        p = tmp_path / "scan.pcapng"
        gen.make_scan_pcap(str(p), n_ports=150)
        r = _upload(client, auth, str(p))
        fid = r.json()["id"]
        r = client.post("/api/v1/analysis", headers=auth, json={"file_id": fid})
        return wait_task(client, auth, r.json()["id"])

    def test_json_report_meta(self, client, auth, tmp_path):
        task = self._succeeded_task(client, auth, tmp_path)
        r = client.get(f"/api/v1/analysis/{task['id']}/report?format=json", headers=auth)
        assert r.status_code == 200
        doc = r.json()
        meta = doc["meta"]
        # 验收：报告包含输入文件哈希、引擎版本、策略版本
        assert len(meta["file"]["sha256"]) == 64
        assert meta["engine_version"].startswith("baize-engine")
        assert meta["strategy_set"]
        assert doc["summary"]["risk"]["score"] >= 0
        assert len(doc["alerts"]) >= 1
        assert len(doc["packets"]) >= 8

    def test_csv_report(self, client, auth, tmp_path):
        task = self._succeeded_task(client, auth, tmp_path)
        r = client.get(f"/api/v1/analysis/{task['id']}/report?format=csv", headers=auth)
        assert r.status_code == 200
        lines = r.text.strip().splitlines()
        assert len(lines) >= 2  # 表头 + 至少一行
        assert "strategy_id" in lines[0]

    def test_html_report(self, client, auth, tmp_path):
        task = self._succeeded_task(client, auth, tmp_path)
        r = client.get(f"/api/v1/analysis/{task['id']}/report?format=html", headers=auth)
        assert r.status_code == 200
        assert "白泽流量分析平台" in r.text
        assert task["file_sha256"] in r.text or "SHA-256" in r.text

    def test_cancel_and_retry_flow(self, client, auth, tmp_path):
        p = tmp_path / "s.pcapng"
        gen.make_scan_pcap(str(p), n_ports=150)
        r = _upload(client, auth, str(p))
        fid = r.json()["id"]
        r = client.post("/api/v1/analysis", headers=auth, json={"file_id": fid})
        tid = r.json()["id"]
        r = client.post(f"/api/v1/analysis/{tid}/cancel", headers=auth)
        assert r.status_code in (200, 400)  # 可能已开始运行
        task = wait_task(client, auth, tid)
        if task["status"] == "cancelled":
            r = client.post(f"/api/v1/analysis/{tid}/retry", headers=auth)
            assert r.status_code == 200
            task = wait_task(client, auth, tid)
        assert task["status"] == "succeeded"


class TestTrash:
    """回收站：删除 → 列表消失 → 还原 → 彻底删除（12.x）。"""

    def _make_task(self, client, auth, tmp_path):
        p = tmp_path / "s.pcapng"
        gen.make_scan_pcap(str(p), n_ports=150)
        r = _upload(client, auth, str(p))
        fid = r.json()["id"]
        r = client.post("/api/v1/analysis", headers=auth, json={"file_id": fid})
        return wait_task(client, auth, r.json()["id"])

    def test_trash_restore_purge(self, client, auth, tmp_path):
        task = self._make_task(client, auth, tmp_path)
        assert task["status"] == "succeeded"
        tid = task["id"]
        # 删除 → 移入回收站，原状态被保存
        r = client.delete(f"/api/v1/analysis/{tid}", headers=auth)
        assert r.status_code == 200
        assert r.json()["status"] == "deleted"
        # 常规列表不再出现
        r = client.get("/api/v1/analysis?page_size=100", headers=auth)
        assert all(i["id"] != tid for i in r.json()["items"])
        # 回收站出现
        r = client.get("/api/v1/analysis?status=deleted", headers=auth)
        items = [i for i in r.json()["items"] if i["id"] == tid]
        assert len(items) == 1
        assert items[0]["config_snapshot"]["restore_status"] == "succeeded"
        # 还原 → 回到常规列表
        r = client.post(f"/api/v1/analysis/{tid}/restore", headers=auth)
        assert r.status_code == 200 and r.json()["status"] == "succeeded"
        r = client.get("/api/v1/analysis?page_size=100", headers=auth)
        assert any(i["id"] == tid for i in r.json()["items"])
        # 再次删除后彻底删除 → 结果数据一并清除
        client.delete(f"/api/v1/analysis/{tid}", headers=auth)
        r = client.delete(f"/api/v1/analysis/{tid}/purge", headers=auth)
        assert r.status_code == 200
        r = client.get("/api/v1/analysis?status=deleted", headers=auth)
        assert all(i["id"] != tid for i in r.json()["items"])
        # 已彻底删除的任务无法再访问
        assert client.get(f"/api/v1/analysis/{tid}", headers=auth).status_code == 404
        # 未删除的任务不允许直接 purge
        task2 = self._make_task(client, auth, tmp_path)
        r = client.delete(f"/api/v1/analysis/{task2['id']}/purge", headers=auth)
        assert r.status_code == 400

    def test_task_list_has_file_name(self, client, auth, tmp_path):
        task = self._make_task(client, auth, tmp_path)
        r = client.get("/api/v1/analysis?page_size=100", headers=auth)
        item = next(i for i in r.json()["items"] if i["id"] == task["id"])
        # 内容相同的流量包被哈希去重，显示规范记录的文件名（首次上传名）
        assert item["file_name"].endswith(".pcapng")
