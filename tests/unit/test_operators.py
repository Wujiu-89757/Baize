"""单元测试：条件算子（文档 6.4/12.1）。"""
import pytest

from app.analysis.operators import evaluate_condition, evaluate_condition_tree, shannon_entropy


def ev(field, op, value, values):
    return evaluate_condition({"field": field, "op": op, "value": value}, values)


class TestComparison:
    def test_numeric(self):
        assert ev("x", "eq", 5, {"x": 5})[0]
        assert not ev("x", "eq", 6, {"x": 5})[0]
        assert ev("x", "neq", 6, {"x": 5})[0]
        assert ev("x", "gt", 4, {"x": 5})[0]
        assert ev("x", "gte", 5, {"x": 5})[0]
        assert ev("x", "lt", 6, {"x": 5})[0]
        assert ev("x", "lte", 5, {"x": 5})[0]
        assert not ev("x", "gt", 5.5, {"x": 5})[0]

    def test_string(self):
        assert ev("s", "eq", "abc", {"s": "abc"})[0]
        assert ev("s", "gt", "aaa", {"s": "abc"})[0]

    def test_bool(self):
        assert ev("b", "eq", True, {"b": True})[0]

    def test_comparator_dict(self):
        assert ev("x", "gte", {"gte": 4, "lte": 6}, {"x": 5})[0]
        assert not ev("x", "gte", {"gte": 4, "lte": 4.5}, {"x": 5})[0]

    def test_missing_field_is_false(self):
        # 文档 8.3：缺失字段为 null，条件不命中（neq 同样不命中，避免误判）
        assert not ev("missing", "neq", "x", {})[0]
        assert not ev("missing", "gt", 0, {})[0]
        assert ev("missing", "is_null", True, {})[0]
        assert not ev("missing", "not_null", True, {})[0]


class TestCollections:
    def test_in_not_in(self):
        assert ev("port", "in", [80, 443, 8080], {"port": 443})[0]
        assert not ev("port", "in", [80, 443], {"port": 8080})[0]
        assert ev("port", "not_in", [80, 443], {"port": 8080})[0]
        assert ev("proto", "in", ["tcp", "udp"], {"proto": "tcp"})[0]


class TestStrings:
    def test_contains(self):
        assert ev("ua", "contains", "curl", {"ua": "curl/8.0"})[0]
        assert ev("ua", "contains", ["curl", "wget"], {"ua": "wget/1.2"})[0]
        assert not ev("ua", "contains", "powershell", {"ua": "curl/8.0"})[0]

    def test_starts_with(self):
        assert ev("path", "starts_with", "/api/", {"path": "/api/v1/x"})[0]

    def test_regex(self):
        assert ev("uri", "regex", r"(?i)\.exe(\?|$)", {"uri": "http://x/a.ExE?d=1"})[0]
        assert not ev("uri", "regex", r"\.exe$", {"uri": "http://x/a.html"})[0]

    def test_regex_catastrophic_timeout(self, monkeypatch):
        # 正则 DoS 防护：灾难性回溯模式在超时后返回 False 而不是卡死
        monkeypatch.setattr("app.analysis.operators.settings.regex_timeout_seconds", 0.5)
        pattern = r"^(a+)+$"
        ok, _ = ev("s", "regex", pattern, {"s": "a" * 40 + "b"})
        assert ok is False


class TestNetwork:
    def test_cidr(self):
        assert ev("ip", "cidr", "192.168.0.0/16", {"ip": "192.168.88.1"})[0]
        assert not ev("ip", "cidr", "10.0.0.0/8", {"ip": "192.168.88.1"})[0]
        assert ev("ip", "cidr", ["10.0.0.0/8", "192.168.0.0/16"], {"ip": "192.168.1.2"})[0]

    def test_port_range(self):
        assert ev("port", "port_range", [1000, 2000], {"port": 1500})[0]
        assert not ev("port", "port_range", [1000, 2000], {"port": 999})[0]
        assert ev("port", "port_range", "1024-65535", {"port": 4444})[0]


class TestEntropy:
    def test_shannon(self):
        assert shannon_entropy("aaaa") == 0.0
        assert shannon_entropy("") == 0.0
        e = shannon_entropy("xkcd8Zq3fLp1mNv9")
        assert 3.5 < e <= 4.2

    def test_entropy_op(self):
        assert ev("q", "entropy", {"gte": 4.0}, {"q": "xkcd8Zq3fLp1mNv9"})[0]
        assert not ev("q", "entropy", {"gte": 5.0}, {"q": "aaaa"})[0]


class TestTree:
    def test_all(self):
        tree = {"all": [
            {"field": "a", "op": "gte", "value": 10},
            {"field": "b", "op": "eq", "value": "x"},
        ]}
        assert evaluate_condition_tree(tree, {"a": 12, "b": "x"})[0]
        assert not evaluate_condition_tree(tree, {"a": 12, "b": "y"})[0]

    def test_any(self):
        tree = {"any": [
            {"field": "a", "op": "gte", "value": 10},
            {"field": "b", "op": "eq", "value": "x"},
        ]}
        assert evaluate_condition_tree(tree, {"a": 1, "b": "x"})[0]
        assert not evaluate_condition_tree(tree, {"a": 1, "b": "y"})[0]

    def test_not(self):
        tree = {"not": {"field": "a", "op": "eq", "value": 1}}
        assert evaluate_condition_tree(tree, {"a": 2})[0]
        assert not evaluate_condition_tree(tree, {"a": 1})[0]

    def test_hits_include_actual(self):
        tree = {"all": [{"field": "n", "op": "gte", "value": 5}]}
        hit, hits = evaluate_condition_tree(tree, {"n": 7})
        assert hit and hits[0]["actual"] == 7 and hits[0]["field"] == "n"

    def test_unknown_op_raises(self):
        with pytest.raises(ValueError):
            evaluate_condition({"field": "a", "op": "shell", "value": 1}, {"a": 1})
