"""条件算子（文档 6.4）：安全、可序列化，禁止任意代码执行。

支持：比较(eq/neq/gt/gte/lt/lte)、集合(in/not_in)、字符串(contains/starts_with/regex)、
网络(cidr/port_range)、统计(entropy)、空值(is_null/not_null)。

regex 防护（文档 6.4：正则必须设置超时和长度限制）：
- 模式长度上限（REGEX_MAX_LENGTH）；
- 用 `regex` 模块的 timeout 参数执行（C 层周期检查，超时抛 TimeoutError），
  避免灾难性回溯卡死引擎（Python 内置 re 引擎持 GIL，线程/子进程方案在
  Windows 受限环境下不可行，故采用 regex 库的进程内超时）；
- 待匹配文本长度上限，防止超大载荷进入正则；
- 策略校验另做嵌套量词静态检查（见 app/analysis/strategies.py）。
"""
from __future__ import annotations

import ipaddress
import math
from typing import Any, Optional

import re as _re
try:
    import regex as _regex  # 支持 timeout 的正则引擎
    _HAVE_REGEX = True
except ImportError:  # pragma: no cover
    _regex = None
    _HAVE_REGEX = False

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("baize.operators")

OPERATORS = {
    "eq", "neq", "gt", "gte", "lt", "lte",
    "in", "not_in",
    "contains", "starts_with", "regex",
    "cidr", "port_range", "entropy",
    "is_null", "not_null",
}

_MAX_TEXT_LEN = 64 * 1024


def _num(v: Any) -> Optional[float]:
    try:
        if isinstance(v, bool):
            return 1.0 if v else 0.0
        f = float(v)
        return f
    except (TypeError, ValueError):
        return None


def _to_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _compile(pattern: str):
    if len(pattern) > settings.regex_max_length:
        log.warning("regex too long, rejected", extra={"extra_fields": {"pattern_len": len(pattern)}})
        return None
    try:
        return _regex.compile(pattern) if _HAVE_REGEX else _re.compile(pattern)
    except _re.error:
        return None


def _regex_match(pattern: str, text: str) -> bool:
    compiled = _compile(pattern)
    if compiled is None:
        return False
    if len(text) > _MAX_TEXT_LEN:
        text = text[:_MAX_TEXT_LEN]
    if _HAVE_REGEX:
        try:
            # regex 模块 timeout 参数：超时抛 TimeoutError（C 层周期检查）
            return compiled.search(text, timeout=settings.regex_timeout_seconds) is not None
        except TimeoutError:
            log.warning("regex timed out",
                        extra={"extra_fields": {"pattern": pattern[:80], "text_len": len(text)}})
            return False
        except Exception:  # noqa: BLE001
            return False
    # 无 regex 模块时的回退：静态拦截已知灾难性模式（双保险）
    if looks_catastrophic(pattern):
        log.warning("regex skipped (catastrophic-looking, no timeout engine)",
                    extra={"extra_fields": {"pattern": pattern[:80]}})
        return False
    try:
        return compiled.search(text) is not None
    except Exception:  # noqa: BLE001
        return False


def looks_catastrophic(pattern: str) -> bool:
    """启发式：检测嵌套量词等典型灾难性回溯结构（如 (a+)+、(a*)*、(a|a)+）。

    策略校验（app/analysis/strategies.py）与运行时回退共用此实现，规则保持一致。
    """
    # 去除转义字符，避免误判字面量
    cleaned = _re.sub(r"\\.", "", pattern)
    # 量词内嵌套量词/分组
    if _re.search(r"\([^)]*[+*][^)]*\)\s*[+*]", cleaned):
        return True
    if _re.search(r"\(\?:\s*\|", cleaned):
        return True
    # 形如 (a|a)+ 的交替重叠
    if _re.search(r"\(([^|()]+)\|\1\)\s*[+*]", cleaned):
        return True
    return False


def _cmp(field: Any, expected: Any, op: str) -> bool:
    """数值优先，其次字符串比较。"""
    if field is None:
        return False
    nf, ne = _num(field), _num(expected)
    if nf is not None and ne is not None:
        if op == "eq":
            return nf == ne
        if op == "neq":
            return nf != ne
        if op == "gt":
            return nf > ne
        if op == "gte":
            return nf >= ne
        if op == "lt":
            return nf < ne
        if op == "lte":
            return nf <= ne
    sf, se = _to_str(field), _to_str(expected)
    if op == "eq":
        return sf == se
    if op == "neq":
        return sf != se
    if op == "gt":
        return sf > se
    if op == "gte":
        return sf >= se
    if op == "lt":
        return sf < se
    if op == "lte":
        return sf <= se
    return False


def shannon_entropy(text: str) -> float:
    """字符串香农熵（bit/char）。"""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def evaluate_condition(cond: dict, values: dict[str, Any]) -> tuple[bool, Any]:
    """计算单条条件。values 为扁平字段字典（缺失字段=null）。

    返回 (是否命中, 实际值)。实际值用于证据展示。
    """
    field = cond.get("field", "")
    op = cond.get("op", "eq")
    expected = cond.get("value")

    if op not in OPERATORS:
        raise ValueError(f"unknown operator: {op}")

    actual = values.get(field)

    if op == "is_null":
        return (actual is None or actual == ""), actual
    if op == "not_null":
        return (actual is not None and actual != ""), actual
    if actual is None:
        return False, actual

    if op in ("eq", "neq", "gt", "gte", "lt", "lte"):
        # 支持 value 为比较器字典，如 {gte: 4.2, lte: 6.0}
        if isinstance(expected, dict):
            ok = True
            for sub_op, sub_val in expected.items():
                if sub_op not in ("eq", "neq", "gt", "gte", "lt", "lte"):
                    raise ValueError(f"invalid comparator in value dict: {sub_op}")
                if not _cmp(actual, sub_val, sub_op):
                    ok = False
                    break
            return ok, actual
        return _cmp(actual, expected, op), actual

    if op == "in":
        items = expected if isinstance(expected, list) else [expected]
        return any(_cmp(actual, item, "eq") for item in items), actual

    if op == "not_in":
        items = expected if isinstance(expected, list) else [expected]
        return not any(_cmp(actual, item, "eq") for item in items), actual

    if op == "contains":
        needles = expected if isinstance(expected, list) else [expected]
        s = _to_str(actual).lower()
        return any(_to_str(n).lower() in s for n in needles), actual

    if op == "starts_with":
        needles = expected if isinstance(expected, list) else [expected]
        s = _to_str(actual)
        return any(s.startswith(_to_str(n)) for n in needles), actual

    if op == "regex":
        patterns = expected if isinstance(expected, list) else [expected]
        s = _to_str(actual)
        return any(_regex_match(_to_str(p), s) for p in patterns), actual

    if op == "cidr":
        nets = expected if isinstance(expected, list) else [expected]
        try:
            addr = ipaddress.ip_address(_to_str(actual))
        except ValueError:
            return False, actual
        for net in nets:
            try:
                if addr.version == ipaddress.ip_network(_to_str(net), strict=False).version and addr in ipaddress.ip_network(_to_str(net), strict=False):
                    return True, actual
            except ValueError:
                continue
        return False, actual

    if op == "port_range":
        n = _num(actual)
        if n is None:
            return False, actual
        ranges = expected if isinstance(expected, list) else [expected]
        # 两个数字的裸列表视为 [lo, hi] 闭区间；嵌套列表/字符串/数字为多个离散区间
        if (isinstance(expected, list) and len(expected) == 2
                and all(not isinstance(x, (list, tuple, str)) for x in expected)):
            ranges = [expected]
        for r in ranges:
            if isinstance(r, (list, tuple)) and len(r) == 2:
                lo, hi = _num(r[0]), _num(r[1])
                if lo is not None and hi is not None and lo <= n <= hi:
                    return True, actual
            elif isinstance(r, str) and "-" in r:
                lo_s, hi_s = r.split("-", 1)
                lo, hi = _num(lo_s), _num(hi_s)
                if lo is not None and hi is not None and lo <= n <= hi:
                    return True, actual
            elif _cmp(n, r, "eq"):
                return True, actual
        return False, actual

    if op == "entropy":
        e = shannon_entropy(_to_str(actual))
        if isinstance(expected, dict):
            ok = True
            for sub_op, sub_val in expected.items():
                if sub_op not in ("eq", "neq", "gt", "gte", "lt", "lte"):
                    raise ValueError(f"invalid comparator in entropy: {sub_op}")
                if not _cmp(e, sub_val, sub_op):
                    ok = False
                    break
            return ok, e
        return _cmp(e, expected, "gte"), e

    raise ValueError(f"operator not implemented: {op}")


def evaluate_condition_tree(tree: dict, values: dict[str, Any]) -> tuple[bool, list[dict]]:
    """条件树：{all: [...]} / {any: [...]} / {not: {...}} / 单条件。

    返回 (是否命中, 命中的条件列表，含实际值)。
    """
    hits: list[dict] = []

    if "all" in tree:
        ok = True
        for sub in tree["all"]:
            hit, sub_hits = evaluate_condition_tree(sub, values)
            hits.extend(sub_hits)
            if not hit:
                ok = False
        return ok, hits

    if "any" in tree:
        ok = False
        for sub in tree["any"]:
            hit, sub_hits = evaluate_condition_tree(sub, values)
            if hit:
                ok = True
                hits.extend(sub_hits)
        return ok, hits

    if "not" in tree:
        hit, _ = evaluate_condition_tree(tree["not"], values)
        return (not hit), []

    # 单条件（field+op+value）
    if "field" in tree:
        hit, actual = evaluate_condition(tree, values)
        if hit:
            hits.append({"field": tree.get("field"), "op": tree.get("op"),
                         "expected": tree.get("value"), "actual": _display_value(actual)})
        return hit, hits

    raise ValueError("invalid condition tree node: " + str(tree)[:80])


def _display_value(v: Any) -> Any:
    if isinstance(v, float):
        return round(v, 4)
    if isinstance(v, (list, dict)):
        import json
        return json.dumps(v, ensure_ascii=False)[:500]
    return v


# 别名导出，保持策略 schema 中 op 名与实现一一对应
def available_operators() -> list[str]:
    return sorted(OPERATORS)
