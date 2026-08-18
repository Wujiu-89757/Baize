"""单元测试：策略校验（文档 6.3/6.6/12.1）。"""
from app.analysis.strategies import validate_strategy

VALID = {
    "id": "test.example.rule",
    "name": "测试规则",
    "version": "1.0.0",
    "category": "scanning",
    "scope": "session",
    "enabled": True,
    "severity": "medium",
    "weight": 30,
    "confidence": 0.7,
    "description": "d",
    "window": {"seconds": 60, "group_by": ["src_ip", "dst_ip"]},
    "conditions": {
        "all": [
            {"field": "session.syn_count", "op": "gte", "value": 100},
            {"field": "session.syn_pure_ratio", "op": "gte", "value": 0.9},
        ]
    },
    "evidence": ["frame.number", "ip.src"],
    "mitre_tags": ["T1046"],
}


def ok(content, expect_valid=True):
    errors, warnings = validate_strategy(content)
    if expect_valid:
        assert not errors, errors
    return errors, warnings


class TestRequired:
    def test_valid_passes(self):
        ok(VALID)

    def test_missing_required(self):
        for field in ("id", "name", "version", "category", "scope", "severity",
                      "weight", "confidence", "conditions"):
            c = dict(VALID)
            del c[field]
            errors, _ = validate_strategy(c)
            assert any(field in e for e in errors), (field, errors)

    def test_bad_id(self):
        c = dict(VALID, id="Bad ID!")
        errors, _ = validate_strategy(c)
        assert any("id" in e for e in errors)

    def test_bad_version(self):
        c = dict(VALID, version="1.0")
        errors, _ = validate_strategy(c)
        assert any("version" in e for e in errors)

    def test_weight_bounds(self):
        for w in (0, 101, -5):
            c = dict(VALID, weight=w)
            errors, _ = validate_strategy(c)
            assert any("weight" in e for e in errors)

    def test_confidence_bounds(self):
        for cf in (-0.1, 1.5):
            c = dict(VALID, confidence=cf)
            errors, _ = validate_strategy(c)
            assert any("confidence" in e for e in errors)

    def test_bad_scope_severity(self):
        c = dict(VALID, scope="galaxy")
        errors, _ = validate_strategy(c)
        assert any("scope" in e for e in errors)
        c = dict(VALID, severity="extreme")
        errors, _ = validate_strategy(c)
        assert any("severity" in e for e in errors)


class TestConditions:
    def test_unknown_op(self):
        c = dict(VALID)
        c["conditions"] = {"field": "x", "op": "run_python", "value": 1}
        errors, _ = validate_strategy(c)
        assert any("op" in e for e in errors)

    def test_unknown_tree_key(self):
        c = dict(VALID)
        c["conditions"] = {"every": [{"field": "x", "op": "eq", "value": 1}]}
        errors, _ = validate_strategy(c)
        assert errors

    def test_nested_tree(self):
        c = dict(VALID)
        c["conditions"] = {
            "any": [
                {"all": [
                    {"field": "frame.number", "op": "eq", "value": 1},
                    {"not": {"field": "http.uri", "op": "eq", "value": "/x"}},
                ]},
                {"field": "tcp.dstport", "op": "in", "value": [80, 443]},
            ]
        }
        ok(c)

    def test_regex_length_limit(self):
        c = dict(VALID)
        c["conditions"] = {"field": "http.uri", "op": "regex", "value": "a" * 1000}
        errors, _ = validate_strategy(c)
        assert any("regex" in e for e in errors)

    def test_in_requires_list(self):
        c = dict(VALID)
        c["conditions"] = {"field": "tcp.dstport", "op": "in", "value": 80}
        errors, _ = validate_strategy(c)
        assert any("value" in e for e in errors)

    def test_missing_value(self):
        c = dict(VALID)
        c["conditions"] = {"field": "tcp.dstport", "op": "eq"}
        errors, _ = validate_strategy(c)
        assert any("value" in e for e in errors)

    def test_unknown_field_rejected(self):
        """拼错字段在发布前被字段注册表拦截（不再静默不命中）。"""
        c = dict(VALID)
        c["conditions"] = {"field": "sesion.syn_count", "op": "gte", "value": 100}
        errors, _ = validate_strategy(c)
        assert any("字段" in e for e in errors)


class TestWindow:
    def test_bad_group_field(self):
        c = dict(VALID)
        c["window"] = {"seconds": 60, "group_by": ["session.nonexistent"]}
        errors, _ = validate_strategy(c)
        assert any("group_by" in e for e in errors)

    def test_seconds_positive(self):
        c = dict(VALID)
        c["window"] = {"seconds": -5, "group_by": ["src_ip"]}
        errors, _ = validate_strategy(c)
        assert any("seconds" in e for e in errors)

    def test_multi(self):
        c = dict(VALID)
        c["window"] = {"seconds": 60, "multi": [1, 10, 60, 300], "group_by": ["src_ip", "dst_ip"]}
        ok(c)

    def test_correlation_warning(self):
        c = dict(VALID, scope="correlation")
        errors, warnings = validate_strategy(c)
        assert not errors
        assert warnings
