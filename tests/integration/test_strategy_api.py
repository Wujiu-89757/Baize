"""集成测试：策略生命周期 API（文档 6.6/6.7/12.3 回放）。"""
import yaml

STRATEGY = {
    "id": "test.api_lifecycle",
    "name": "API 生命周期测试策略",
    "version": "1.0.0",
    "category": "scanning",
    "scope": "packet",
    "enabled": False,
    "severity": "low",
    "weight": 10,
    "confidence": 0.5,
    "conditions": {"field": "tcp.dstport", "op": "eq", "value": 31337},
    "evidence": ["frame.number", "tcp.dstport"],
}


class TestStrategyLifecycle:
    def test_full_lifecycle(self, client, auth):
        # 创建草稿
        r = client.post("/api/v1/strategies", headers=auth, json={"content": STRATEGY})
        assert r.status_code == 200, r.text
        sid = STRATEGY["id"]
        # 草稿未发布不能启用
        r = client.post(f"/api/v1/strategies/{sid}/enable", headers=auth)
        assert r.status_code == 409
        # 校验接口
        r = client.post(f"/api/v1/strategies/{sid}/validate", headers=auth,
                        json={"content": STRATEGY})
        assert r.status_code == 200 and r.json()["valid"] is True
        # 发布
        r = client.post(f"/api/v1/strategies/{sid}/publish", headers=auth)
        assert r.status_code == 200
        d = r.json()
        assert d["meta"]["current_version"] == "1.0.0"
        assert d["versions"][0]["status"] == "published"
        # 启用
        r = client.post(f"/api/v1/strategies/{sid}/enable", headers=auth)
        assert r.status_code == 200 and r.json()["enabled"] is True
        # 修改生成新草稿版本，已发布版本不可变
        c2 = dict(STRATEGY, version="1.1.0", weight=20)
        r = client.put(f"/api/v1/strategies/{sid}", headers=auth, json={"content": c2})
        assert r.status_code == 200
        versions = {v["version"]: v["status"] for v in r.json()["versions"]}
        assert versions["1.0.0"] == "published"
        assert versions["1.1.0"] == "draft"
        # 同版本冲突
        r = client.put(f"/api/v1/strategies/{sid}", headers=auth, json={"content": c2})
        assert r.status_code == 409
        # 停用
        r = client.post(f"/api/v1/strategies/{sid}/disable", headers=auth)
        assert r.status_code == 200 and r.json()["enabled"] is False
        # 列表过滤
        r = client.get(f"/api/v1/strategies?q={sid}", headers=auth)
        assert r.json()["total"] == 1

    def test_invalid_strategy_rejected(self, client, auth):
        bad = dict(STRATEGY, id="Bad ID!", weight=999)
        r = client.post("/api/v1/strategies", headers=auth, json={"content": bad})
        assert r.status_code == 422
        assert r.json()["detail"]["errors"]

    def test_correlation_cannot_publish(self, client, auth):
        """correlation scope 只允许草稿，发布必须被拒绝（回归：曾发布后仍被当普通策略执行）。"""
        c = dict(STRATEGY, id="test.corr_reject", scope="correlation")
        r = client.post("/api/v1/strategies", headers=auth, json={"content": c})
        assert r.status_code == 200
        r = client.post("/api/v1/strategies/test.corr_reject/publish", headers=auth)
        assert r.status_code == 422
        assert "correlation" in r.json()["detail"]["errors"][0]

    def test_typo_field_rejected_on_create(self, client, auth):
        """拼错字段在创建/发布前被字段注册表拦截，不再静默不命中。"""
        bad = dict(STRATEGY, id="test.typo_field")
        bad["conditions"] = {"field": "sesion.syn_count", "op": "gte", "value": 10}
        r = client.post("/api/v1/strategies", headers=auth, json={"content": bad})
        assert r.status_code == 422
        assert any("字段" in e for e in r.json()["detail"]["errors"])

    def test_create_with_text_and_publish_single_request(self, client, auth):
        """创建/发布单事务：直接提交 text+publish，一次请求即发布成功（简化调用链）。"""
        import yaml
        c = dict(STRATEGY, id="test.text_publish", version="1.0.0")
        text = yaml.safe_dump(c, allow_unicode=True)
        r = client.post("/api/v1/strategies", headers=auth,
                        json={"text": text, "publish": True, "enabled": True})
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["meta"]["current_version"] == "1.0.0"
        assert d["meta"]["enabled"] is True

    def test_import_export(self, client, auth):
        yaml_text = yaml.safe_dump(STRATEGY, allow_unicode=True)
        r = client.post("/api/v1/strategies/parse-yaml", headers=auth, json={"text": yaml_text})
        assert r.status_code == 200
        assert r.json()["content"]["id"] == STRATEGY["id"]
        # 导入（create 模式已存在 → 跳过）
        r = client.post("/api/v1/strategies/import", headers=auth,
                        json={"items": [r.json()["content"]], "mode": "create"})
        assert r.status_code == 200
        assert STRATEGY["id"] in r.json()["skipped"]
        # 导出
        r = client.get("/api/v1/strategies/export", headers=auth)
        assert r.status_code == 200
        assert "test.api_lifecycle" in r.text
