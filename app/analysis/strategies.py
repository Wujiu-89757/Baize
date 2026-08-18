"""策略加载与校验（文档 6.3/6.6）。策略是纯数据（YAML/JSON），不执行代码。"""
from __future__ import annotations

import json
import re
import warnings as _warnings
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.analysis.fields import GROUP_KEY_FIELDS, is_supported_field
from app.analysis.operators import OPERATORS, looks_catastrophic
from app.core.config import settings
from app.core.logging import get_logger
from app.models.strategy import SCOPES, SEVERITIES

log = get_logger("baize.strategies")

_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{2,63}$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# 条件树中允许的键
_TREE_KEYS = {"all", "any", "not", "field", "op", "value"}
# 需要列表值的算子
_LIST_OPS = {"in", "not_in"}
_STRING_OPS = {"contains", "starts_with", "regex"}


@lru_cache(maxsize=1)
def _json_schema() -> dict:
    """读取策略 JSON Schema（字段注册表与运行时校验的共同参考物）。"""
    schema_path = settings.strategy_dir / "schemas" / "strategy.schema.json"
    if schema_path.exists():
        return json.loads(schema_path.read_text(encoding="utf-8"))
    return {}


def _validate_condition(node: Any, errors: list[str], path: str = "conditions") -> None:
    if not isinstance(node, dict):
        errors.append(f"{path}: 条件必须是对象")
        return
    unknown = set(node.keys()) - _TREE_KEYS
    if unknown:
        errors.append(f"{path}: 未知条件键 {sorted(unknown)}")
        return
    if "all" in node or "any" in node:
        for key in ("all", "any"):
            if key in node:
                subs = node[key]
                if not isinstance(subs, list) or not subs:
                    errors.append(f"{path}.{key}: 必须是非空数组")
                    continue
                for i, sub in enumerate(subs):
                    _validate_condition(sub, errors, f"{path}.{key}[{i}]")
        return
    if "not" in node:
        _validate_condition(node["not"], errors, f"{path}.not")
        return
    field = node.get("field")
    op = node.get("op")
    value = node.get("value")
    if not isinstance(field, str) or not field:
        errors.append(f"{path}: 缺少 field")
        return
    if not is_supported_field(field):
        errors.append(f"{path}: 字段 {field!r} 不在统一字段注册表，检查拼写（见 /api/v1/strategies/meta）")
        return
    if op not in OPERATORS:
        errors.append(f"{path}: 不支持的算子 {op!r}，可用: {sorted(OPERATORS)}")
        return
    if "value" not in node:
        errors.append(f"{path}: 缺少 value")
        return
    if op in _LIST_OPS and not isinstance(value, list):
        errors.append(f"{path}.{op}: value 必须是列表")
    if op in _STRING_OPS:
        vals = value if isinstance(value, list) else [value]
        for v in vals:
            if not isinstance(v, str) or len(v) > settings.regex_max_length + 500:
                errors.append(f"{path}.{op}: 模式必须是字符串且长度受限")
            elif op == "regex" and looks_catastrophic(v):
                errors.append(f"{path}.regex: 模式疑似灾难性回溯（嵌套量词/重叠分支），请简化")
    if op in ("eq", "neq", "gt", "gte", "lt", "lte", "entropy"):
        if isinstance(value, dict):
            for sub_op, sub_val in value.items():
                if sub_op not in ("eq", "neq", "gt", "gte", "lt", "lte"):
                    errors.append(f"{path}.{op}: 比较器字典含非法键 {sub_op}")
                elif not isinstance(sub_val, (int, float)) and not isinstance(sub_val, str):
                    errors.append(f"{path}.{op}.{sub_op}: 比较值必须是数字或字符串")
        elif not isinstance(value, (int, float, str, bool)):
            errors.append(f"{path}.{op}: value 必须是数字/字符串/布尔")


def validate_strategy(content: dict) -> tuple[list[str], list[str]]:
    """返回 (errors, warnings)。"""
    errors: list[str] = []
    warnings_: list[str] = []

    if not isinstance(content, dict):
        return ["策略必须是 YAML/JSON 对象"], []

    for req in ("id", "name", "version", "category", "scope", "severity", "weight", "confidence", "conditions"):
        if req not in content:
            errors.append(f"缺少必填字段 {req}")

    sid = content.get("id", "")
    if sid and not _ID_RE.match(sid):
        errors.append(f"id {sid!r} 必须匹配 {_ID_RE.pattern}")
    ver = content.get("version", "")
    if ver and not _SEMVER_RE.match(str(ver)):
        errors.append(f"version {ver!r} 必须是语义化版本 x.y.z")
    scope = content.get("scope", "")
    if scope and scope not in SCOPES:
        errors.append(f"scope {scope!r} 必须是 {SCOPES}")
    sev = content.get("severity", "")
    if sev and sev not in SEVERITIES:
        errors.append(f"severity {sev!r} 必须是 {SEVERITIES}")
    weight = content.get("weight")
    if weight is not None:
        if not isinstance(weight, (int, float)) or not (1 <= weight <= 100):
            errors.append("weight 必须是 1~100 的数字")
    conf = content.get("confidence")
    if conf is not None:
        if not isinstance(conf, (int, float)) or not (0 <= conf <= 1):
            errors.append("confidence 必须是 0~1 的数字")
    if scope == "correlation":
        warnings_.append("correlation（关联）scope 在 v0.1 中不执行，仅允许草稿")

    window = content.get("window")
    if window is not None:
        if not isinstance(window, dict):
            errors.append("window 必须是对象 {seconds, group_by, multi?}")
        else:
            seconds = window.get("seconds")
            if seconds is not None and (not isinstance(seconds, (int, float)) or seconds <= 0):
                errors.append("window.seconds 必须是正数")
            gb = window.get("group_by", [])
            if not isinstance(gb, list):
                errors.append("window.group_by 必须是字段名列表")
            else:
                for f in gb:
                    if f not in GROUP_KEY_FIELDS:
                        errors.append(f"window.group_by 不支持字段 {f!r}，可用: {sorted(GROUP_KEY_FIELDS)}")
            multi = window.get("multi", [])
            if not isinstance(multi, list):
                errors.append("window.multi 必须是秒数列表")
            elif multi:
                for m in multi:
                    if not isinstance(m, (int, float)) or m <= 0:
                        errors.append(f"window.multi 含非法值 {m!r}")

    if "conditions" in content:
        _validate_condition(content["conditions"], errors)

    evidence = content.get("evidence")
    if evidence is not None and not isinstance(evidence, list):
        errors.append("evidence 必须是字段名列表")
    tags = content.get("tags")
    if tags is not None and not isinstance(tags, list):
        errors.append("tags 必须是列表")
    mitre = content.get("mitre_tags")
    if mitre is not None and not isinstance(mitre, list):
        errors.append("mitre_tags 必须是列表")

    # JSON Schema 校验：schema 与字段注册表共同构成"统一字段契约"（文档 6.6）
    schema_errors = _schema_errors(content)
    errors.extend(schema_errors)

    return errors, warnings_


def _schema_errors(content: dict) -> list[str]:
    """用 strategies/schemas/strategy.schema.json 校验结构。schema 缺失时跳过。"""
    schema = _json_schema()
    if not schema:
        return []
    try:
        from jsonschema import Draft7Validator
        validator = Draft7Validator(schema)
        errs = sorted(validator.iter_errors(content), key=lambda e: list(e.path))
        return [f"schema: {'.'.join(str(p) for p in e.path) or '(root)'}: {e.message}"
                for e in errs[:20]]
    except ImportError:  # jsonschema 未安装时退化为手写校验（不影响核心字段校验）
        return []
    except Exception as exc:  # noqa: BLE001
        log.warning("json schema validation failed to run",
                    extra={"extra_fields": {"error": str(exc)}})
        return []


def _load_yaml_file(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_builtin_strategies() -> list[dict]:
    """加载 strategies/builtin 下的全部策略定义。"""
    builtin_dir = settings.strategy_dir / "builtin"
    out: list[dict] = []
    if not builtin_dir.is_dir():
        return out
    for path in sorted(builtin_dir.glob("*.yaml")):
        try:
            content = _load_yaml_file(path)
            errors, _ = validate_strategy(content)
            if errors:
                log.warning("builtin strategy invalid, skipped", extra={
                    "extra_fields": {"file": path.name, "errors": errors}})
                continue
            out.append(content)
        except Exception as exc:  # noqa: BLE001
            log.warning("failed to load builtin strategy", extra={
                "extra_fields": {"file": path.name, "error": str(exc)}})
    return out


def strategy_to_yaml(content: dict) -> str:
    return yaml.safe_dump(content, allow_unicode=True, sort_keys=False)


def strategy_from_yaml(text: str) -> dict:
    with _warnings.catch_warnings():
        _warnings.simplefilter("ignore")
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("YAML 顶层必须是对象")
    return data
