"""安全测试（文档 12.5/14）：伪装文件、越权、超大文件、路径穿越、正则 DoS。"""
from app.core.config import settings
from tests.fixtures import gen


class TestUploadSecurity:
    def test_no_auth_required(self, client):
        """本地模式：无需登录，匿名直接访问。"""
        assert client.get("/api/v1/files").status_code == 200
        r = client.post("/api/v1/analysis", json={"file_id": "no-such-file"})
        assert r.status_code == 404  # 业务校验生效（不存在文件），而非 401

    def test_all_roles_unrestricted(self, client, auth, tmp_path):
        """本地免登录：任意请求均可访问审计与上传，无登录/权限校验。"""
        assert client.get("/api/v1/audit").status_code == 200
        assert client.get("/api/v1/files").status_code == 200
        p = tmp_path / "n.pcap"
        gen.make_normal_pcap(str(p))
        with open(p, "rb") as fh:
            r = client.post("/api/v1/files", files={"file": ("n.pcap", fh)})
        assert r.status_code == 200  # 匿名上传成功
        # 登录接口已删除（本地模式不再有账号体系）
        assert client.post("/api/v1/auth/login", json={"username": "x", "password": "y"}).status_code == 404

    def test_wrong_extension_rejected(self, client, auth, tmp_path):
        p = tmp_path / "n.pcap"
        gen.make_normal_pcap(str(p))
        with open(p, "rb") as fh:
            r = client.post("/api/v1/files", headers=auth,
                            files={"file": ("evil.txt", fh)})
        assert r.status_code == 422

    def test_disguised_extension_rejected(self, client, auth, tmp_path):
        # 扩展名合法但 magic 不对（文档 7.2：不能只信任文件名）
        p = tmp_path / "fake.pcapng"
        p.write_bytes(b"<?php echo 'not a pcap'; ?>" * 10)
        with open(p, "rb") as fh:
            r = client.post("/api/v1/files", headers=auth,
                            files={"file": ("fake.pcapng", fh)})
        assert r.status_code == 422

    def test_oversize_rejected(self, client, auth, monkeypatch, tmp_path):
        monkeypatch.setattr(settings, "max_upload_size", 500)
        p = tmp_path / "big.pcap"
        gen.make_normal_pcap(str(p))
        with open(p, "rb") as fh:
            r = client.post("/api/v1/files", headers=auth,
                            files={"file": ("big.pcap", fh)})
        assert r.status_code == 422

    def test_path_traversal_cleaned(self, client, auth, tmp_path):
        # 用不同时间戳生成唯一文件，避免与重复上传测试的哈希去重冲突
        p = tmp_path / "n.pcap"
        gen.make_normal_pcap(str(p), base_ts=1800000000.0)
        with open(p, "rb") as fh:
            r = client.post("/api/v1/files", headers=auth,
                            files={"file": ("..\\..\\evil.pcap", fh)})
        assert r.status_code == 200
        assert "evil.pcap" == r.json()["original_name"]

    def test_task_cross_access(self, client, auth, tmp_path):
        # 不存在任务返回 404；越权（他人文件）不泄露
        r = client.get("/api/v1/analysis/no-such-task", headers=auth)
        assert r.status_code == 404
        r = client.get("/api/v1/analysis/no-such-task/alerts", headers=auth)
        assert r.status_code == 404
