"""单元测试：评分引擎（文档 8.4/12.1）。"""
import pytest

from app.analysis.scoring import context_multiplier, hit_score, level_of, normalize, severity_multiplier


class TestScoring:
    def test_severity_multipliers(self):
        assert severity_multiplier("info") == 0.25
        assert severity_multiplier("low") == 0.5
        assert severity_multiplier("medium") == 1.0
        assert severity_multiplier("high") == 1.5
        assert severity_multiplier("critical") == 2.0
        assert severity_multiplier("unknown") == 1.0

    def test_hit_score_formula(self):
        # weight × confidence × severity_multiplier
        assert hit_score(70, 0.85, "high") == 70 * 0.85 * 1.5
        assert hit_score(70, 0.85, "high", 1.05) == round(70 * 0.85 * 1.5 * 1.05, 4)

    def test_context_multiplier(self):
        assert context_multiplier("scanning", 8, 300) == 1.1
        assert context_multiplier("scanning", 2, 300) == 1.05
        assert context_multiplier("dns", 8, 300) == 1.0
        assert context_multiplier("scanning", 1, 10) == 1.0

    def test_level_boundaries(self):
        assert level_of(0) == "info"
        assert level_of(19.9) == "info"
        assert level_of(20) == "low"
        assert level_of(40) == "medium"
        assert level_of(70) == "high"
        assert level_of(90) == "critical"
        assert level_of(100) == "critical"

    def test_normalize_single(self):
        alerts = [{"strategy_id": "s1", "raw_score": 80.0}]
        total, level = normalize(alerts)
        # 80 / 200 * 100 = 40 → medium
        assert total == 40.0
        assert level == "medium"
        assert alerts[0]["normalized_score"] == 40.0

    def test_normalize_never_exceeds_100(self):
        """任何输入，最终风险分都不超过 100（回归：原实现可到 200）。"""
        cases = [
            [{"strategy_id": f"s{i}", "raw_score": 100.0} for i in range(10)],
            [{"strategy_id": "s1", "raw_score": 200.0}],
            [{"strategy_id": "s1", "raw_score": 90.0},
             {"strategy_id": "s2", "raw_score": 90.0},
             {"strategy_id": "s3", "raw_score": 90.0}],
            [{"strategy_id": "s1", "raw_score": 40.0} for _ in range(10)],
        ]
        for alerts in cases:
            total, _ = normalize(alerts)
            assert total <= 100.0, (total, alerts)
            assert sum(a["normalized_score"] for a in alerts) <= 100.0 + 1e-6

    def test_normalize_per_strategy_cap(self):
        # 同一策略大量命中不允许无限累加（文档 8.4：重复命中设置上限）
        alerts = [{"strategy_id": "s1", "raw_score": 40.0} for _ in range(10)]
        total, level = normalize(alerts)
        # 10×40=400 → 策略封顶 100 → 100/200*100 = 50 → medium
        assert total == 50.0
        assert level == "medium"
        assert sum(a["normalized_score"] for a in alerts) == pytest.approx(50.0, abs=0.01)
        # 单策略内各告警按比例分摊策略上限
        assert alerts[0]["normalized_score"] == pytest.approx(5.0, abs=0.01)

    def test_normalize_total_cap(self):
        alerts = [
            {"strategy_id": "s1", "raw_score": 90.0},
            {"strategy_id": "s2", "raw_score": 90.0},
            {"strategy_id": "s3", "raw_score": 90.0},
        ]
        total, _ = normalize(alerts)
        # 每策略 90 → 任务原始分 270 → 归一化上限 200 → 200/200*100 = 100
        assert total == 100.0

    def test_level_boundaries_normalized(self):
        """归一化后的 0~100 分直接映射五级风险阈值。

        单策略原始分上限 100，因此超过 50 分的归一化值需要多个策略共同构成任务原始分。
        """
        cases = [
            ([{"strategy_id": "s1", "raw_score": 40.0}], 20.0, "low"),
            ([{"strategy_id": "s1", "raw_score": 80.0}], 40.0, "medium"),
            ([{"strategy_id": "s1", "raw_score": 100.0},
              {"strategy_id": "s2", "raw_score": 40.0}], 70.0, "high"),
            ([{"strategy_id": "s1", "raw_score": 100.0},
              {"strategy_id": "s2", "raw_score": 80.0}], 90.0, "critical"),
            ([{"strategy_id": "s1", "raw_score": 100.0},
              {"strategy_id": "s2", "raw_score": 100.0}], 100.0, "critical"),
            ([], 0.0, "info"),
        ]
        for alerts, expect_total, expect_level in cases:
            total, level = normalize(alerts)
            assert total == expect_total, (alerts, total)
            assert level == expect_level, (alerts, total, level)
