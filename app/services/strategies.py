"""策略库服务（文档 6.6/6.7）：CRUD、校验、版本、启停、发布、导入导出。"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

import yaml
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.analysis.strategies import load_builtin_strategies, strategy_from_yaml, strategy_to_yaml, validate_strategy
from app.core.errors import ConflictError, NotFoundError, StrategyValidationError
from app.models import Strategy, StrategyVersion


def list_strategies(session: Session, page: int = 1, page_size: int = 20,
                    category: str = "", scope: str = "", enabled: Optional[bool] = None,
                    tag: str = "", q: str = "") -> tuple[list[Strategy], int]:
    query = session.query(Strategy)
    if category:
        query = query.filter(Strategy.category == category)
    if scope:
        query = query.filter(Strategy.scope == scope)
    if enabled is not None:
        query = query.filter(Strategy.enabled == enabled)
    if q:
        query = query.filter(Strategy.name.contains(q) | Strategy.id.contains(q))
    total = query.count()
    rows = query.order_by(Strategy.category, Strategy.id).offset((page - 1) * page_size).limit(page_size).all()
    if tag:
        rows = [r for r in rows if tag in _versions_content_tags(session, r.id)]
        total = len(rows)
    return rows, total


def _versions_content_tags(session: Session, strategy_id: str) -> list[str]:
    v = session.query(StrategyVersion).filter(
        StrategyVersion.strategy_id == strategy_id).order_by(StrategyVersion.id.desc()).first()
    if not v:
        return []
    return v.content.get("tags", []) or []


def list_enabled_published_versions(session: Session) -> list[tuple[Strategy, StrategyVersion]]:
    """一条 join 查询取得全部启用策略及其当前发布版本（避免分页截断 + N 次版本查询）。

    同一策略仅允许一个 published 版本，但为稳妥仍取"最新发布的版本"。
    """
    latest = (session.query(StrategyVersion.strategy_id,
                            func.max(StrategyVersion.id).label("max_id"))
              .filter(StrategyVersion.status == "published")
              .group_by(StrategyVersion.strategy_id).subquery())
    return (session.query(Strategy, StrategyVersion)
            .join(latest, latest.c.strategy_id == Strategy.id)
            .join(StrategyVersion, StrategyVersion.id == latest.c.max_id)
            .filter(Strategy.enabled == True)  # noqa: E712  只以元数据 enabled 为准
            .order_by(Strategy.category, Strategy.id).all())


def get_published_versions(session: Session, strategy_ids: list[str]) -> dict[str, StrategyVersion]:
    """一次查询返回这些策略的当前发布版本（id -> 版本行）。"""
    if not strategy_ids:
        return {}
    latest = (session.query(StrategyVersion.strategy_id,
                            func.max(StrategyVersion.id).label("max_id"))
              .filter(StrategyVersion.status == "published",
                      StrategyVersion.strategy_id.in_(strategy_ids))
              .group_by(StrategyVersion.strategy_id).subquery())
    rows = (session.query(StrategyVersion)
            .join(latest, latest.c.max_id == StrategyVersion.id).all())
    return {r.strategy_id: r for r in rows}


def get_strategy(session: Session, strategy_id: str) -> Strategy:
    row = session.get(Strategy, strategy_id)
    if row is None:
        raise NotFoundError(f"策略不存在: {strategy_id}")
    return row


def list_versions(session: Session, strategy_id: str) -> list[StrategyVersion]:
    return (session.query(StrategyVersion)
            .filter(StrategyVersion.strategy_id == strategy_id)
            .order_by(StrategyVersion.id.desc()).all())


def get_version(session: Session, strategy_id: str, version: str) -> StrategyVersion:
    row = (session.query(StrategyVersion)
           .filter(StrategyVersion.strategy_id == strategy_id,
                   StrategyVersion.version == version)
           .order_by(StrategyVersion.id.desc()).first())
    if row is None:
        raise NotFoundError(f"策略版本不存在: {strategy_id}@{version}")
    return row


def get_published_content(session: Session, strategy_id: str) -> Optional[dict]:
    """当前发布版本的完整内容（兼容旧调用）。"""
    row = (session.query(StrategyVersion)
           .filter(StrategyVersion.strategy_id == strategy_id,
                   StrategyVersion.status == "published")
           .order_by(StrategyVersion.id.desc()).first())
    return row.content if row else None


def create_strategy(session: Session, content: dict, username: str = "") -> Strategy:
    sid = content.get("id", "")
    if session.get(Strategy, sid) is not None:
        raise ConflictError(f"策略 ID 已存在: {sid}")
    errors, warnings = validate_strategy(content)
    if errors:
        raise StrategyValidationError("策略校验失败", detail={"errors": errors, "warnings": warnings})
    # 启停属于策略元数据：新建策略一律停用，由 set_enabled/发布流程显式启用
    row = Strategy(id=sid, name=content.get("name", sid), category=content.get("category", ""),
                   scope=content.get("scope", "packet"), enabled=False,
                   description=content.get("description", ""), author=content.get("author", username))
    session.add(row)
    session.add(_make_version(session, content, status="draft"))
    session.flush()
    return row


def update_strategy_draft(session: Session, strategy_id: str, content: dict) -> StrategyVersion:
    """修改策略：内容变更总是生成新草稿版本，已发布版本不可变。"""
    row = get_strategy(session, strategy_id)
    if content.get("id") != strategy_id:
        raise StrategyValidationError("策略 id 不可变更", detail={"errors": ["id 不可修改"]})
    errors, warnings = validate_strategy(content)
    if errors:
        raise StrategyValidationError("策略校验失败", detail={"errors": errors, "warnings": warnings})
    version = _make_version(session, content, status="draft")
    session.add(version)
    row.name = content.get("name", row.name)
    row.category = content.get("category", row.category)
    row.scope = content.get("scope", row.scope)
    row.description = content.get("description", "")
    session.flush()
    return version


def _make_version(session: Session, content: dict, status: str = "draft") -> StrategyVersion:
    version = content.get("version", "0.0.1")
    existing = (session.query(StrategyVersion)
                .filter(StrategyVersion.strategy_id == content["id"],
                        StrategyVersion.version == version).count())
    if existing:
        raise ConflictError(f"版本 {version} 已存在，请递增版本号")
    return StrategyVersion(strategy_id=content["id"], version=version,
                           status=status, content=content,
                           created_at=datetime.now(timezone.utc))


def publish_version(session: Session, strategy_id: str, username: str = "",
                    version: Optional[str] = None) -> StrategyVersion:
    """发布：draft/validated → published。历史任务继续引用执行时版本。"""
    row = get_strategy(session, strategy_id)
    versions = list_versions(session, strategy_id)
    if not versions:
        raise NotFoundError("没有可发布的版本")
    if version:
        target = get_version(session, strategy_id, version)
    else:
        # 取最新的 draft/validated 版本
        target = next((v for v in versions if v.status in ("draft", "validated")), None)
        if target is None:
            target = versions[0]
    if target.status == "archived":
        raise ConflictError("已归档版本不能发布")
    if target.content.get("scope") == "correlation":
        raise StrategyValidationError(
            "correlation 关联 scope 暂无执行器，不允许发布", detail={"errors": ["correlation 发布被拒绝"]})
    errors, _ = validate_strategy(target.content)
    if errors:
        raise StrategyValidationError("发布前必须通过校验", detail={"errors": errors})
    # 同策略其他版本降级为 disabled（同一时刻仅一个 published）
    for v in versions:
        if v.id != target.id and v.status == "published":
            v.status = "disabled"
    target.status = "published"
    target.published_by = username
    target.published_at = datetime.now(timezone.utc)
    row.current_version = target.version
    session.flush()
    return target


def set_enabled(session: Session, strategy_id: str, enabled: bool) -> Strategy:
    row = get_strategy(session, strategy_id)
    if enabled and not row.current_version:
        raise ConflictError("请先发布版本再启用")
    row.enabled = enabled
    session.flush()
    return row


def export_strategies(session: Session, ids: Optional[list[str]] = None) -> str:
    query = session.query(StrategyVersion).filter(StrategyVersion.status == "published")
    if ids:
        query = query.filter(StrategyVersion.strategy_id.in_(ids))
    rows = query.order_by(StrategyVersion.strategy_id).all()
    return yaml.safe_dump([r.content for r in rows], allow_unicode=True, sort_keys=False)


def import_strategies(session: Session, items: list[dict], mode: str = "create",
                      username: str = "") -> dict:
    result: dict[str, list] = {"created": [], "updated": [], "skipped": [], "errors": []}
    for content in items:
        sid = content.get("id", "")
        errors, _ = validate_strategy(content)
        if errors:
            result["errors"].append({"id": sid, "errors": errors})
            continue
        existing = session.get(Strategy, sid)
        if existing:
            if mode == "skip":
                result["skipped"].append(sid)
                continue
            if mode == "update":
                try:
                    update_strategy_draft(session, sid, content)
                    result["updated"].append(sid)
                except ConflictError:
                    result["skipped"].append(sid)
                continue
            result["skipped"].append(sid)
            continue
        create_strategy(session, content, username=username)
        result["created"].append(sid)
    session.flush()
    return result


def parse_yaml_documents(text: str) -> list[dict]:
    """解析多文档 YAML（--- 分隔）或 JSON 数组，供导入接口直接消费。"""
    text = text.strip()
    if text.startswith("["):
        data = json.loads(text)
        if not isinstance(data, list):
            raise StrategyValidationError("JSON 顶层必须是数组")
        return [d for d in data if isinstance(d, dict)]
    import re as _re
    items: list[dict] = []
    for chunk in _re.split(r"(?m)^---\s*$", text):
        if chunk.strip():
            item = content_from_text(chunk)
            items.append(item)
    return items


def seed_builtin(session: Session, force: bool = False) -> dict:
    """将 strategies/builtin 下的策略导入数据库（缺失才导入）。"""
    result = {"created": [], "skipped": []}
    for content in load_builtin_strategies():
        sid = content["id"]
        if session.get(Strategy, sid) is None:
            create_strategy(session, content, username="builtin")
            # 内置策略自动发布并启用
            publish_version(session, sid, username="builtin", version=content["version"])
            set_enabled(session, sid, True)
            result["created"].append(sid)
        else:
            result["skipped"].append(sid)
    session.flush()
    return result


def content_from_text(text: str) -> dict:
    """从 YAML/JSON 文本解析策略内容。"""
    text = text.strip()
    if text.startswith("{"):
        data = json.loads(text)
    else:
        data = strategy_from_yaml(text)
    if not isinstance(data, dict):
        raise StrategyValidationError("策略内容必须是对象")
    return data


def content_to_text(content: dict) -> str:
    return strategy_to_yaml(content)
