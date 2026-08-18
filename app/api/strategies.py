"""策略库接口（文档 6.7）。

创建/更新接口接受 {content|text, publish, enabled}，服务端一次解析、校验、保存并可选发布，
保证单事务，替代"parse-yaml → validate → create/update → publish"的多次往返。
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_current_user, get_db
from app.analysis.fields import ALL_FIELDS_SORTED, GROUP_KEY_FIELDS
from app.analysis.operators import available_operators
from app.analysis.strategies import validate_strategy
from app.core.errors import ValidationError
from app.models import Strategy
from app.schemas.api import (Page, StrategyDetail, StrategyImportRequest, StrategyImportResult,
                             StrategyMetaOut, StrategyUpsert, StrategyVersionOut, ValidateResponse)
from app.services import audit, strategies as svc

router = APIRouter(prefix="/api/v1/strategies", tags=["strategies"])


def _meta_out(row: Strategy) -> StrategyMetaOut:
    return StrategyMetaOut(
        id=row.id, name=row.name, category=row.category, scope=row.scope,
        enabled=row.enabled, current_version=row.current_version,
        description=row.description, author=row.author,
        created_at=row.created_at, updated_at=row.updated_at,
    )


def _resolve_content(body: StrategyUpsert) -> dict:
    if body.text is not None:
        return svc.content_from_text(body.text)
    return body.content


@router.get("", response_model=Page)
def list_strategies(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=200),
                    category: str = "", scope: str = "", enabled: Optional[bool] = None,
                    tag: str = "", q: str = "", db: Session = Depends(get_db),
                    user=Depends(get_current_user)):
    rows, total = svc.list_strategies(db, page, page_size, category, scope, enabled, tag, q)
    return Page(total=total, items=[_meta_out(r) for r in rows], page=page, page_size=page_size)


@router.post("", response_model=StrategyDetail)
def create_strategy(body: StrategyUpsert, request: Request, db: Session = Depends(get_db),
                    user=Depends(get_current_user)):
    content = _resolve_content(body)
    row = svc.create_strategy(db, content, username=user.username)
    if body.publish:
        svc.publish_version(db, row.id, username=user.username)
    if body.enabled is not None:
        svc.set_enabled(db, row.id, body.enabled)
    audit.log_audit(db, user_id=user.id, username=user.username, action="strategy.create",
                    target_type="strategy", target_id=row.id,
                    detail={"publish": body.publish}, ip=client_ip(request))
    db.commit()
    return _detail(db, row.id)


@router.post("/import", response_model=StrategyImportResult)
def import_strategies(body: StrategyImportRequest, request: Request,
                      db: Session = Depends(get_db), user=Depends(get_current_user)):
    """直接接受多文档 YAML/JSON 文本（或 items），服务端解析 + 导入单次完成。"""
    if body.text is not None:
        items = svc.parse_yaml_documents(body.text)
    else:
        items = body.items or []
    result = svc.import_strategies(db, items, mode=body.mode, username=user.username)
    audit.log_audit(db, user_id=user.id, username=user.username, action="strategy.import",
                    target_type="strategy", target_id=f"{len(result['created'])}/{len(result['updated'])}",
                    detail=result, ip=client_ip(request))
    db.commit()
    return StrategyImportResult(**result)


@router.post("/parse-yaml")
def parse_yaml(body: dict, db: Session = Depends(get_db),
               user=Depends(get_current_user)):
    """将 YAML/JSON 文本转换为策略对象（编辑器校验用，服务端 PyYAML 解析）。"""
    try:
        return {"content": svc.content_from_text(body.get("text", ""))}
    except Exception as exc:  # noqa: BLE001
        raise ValidationError(f"YAML 解析失败: {exc}")


@router.post("/to-yaml")
def to_yaml(body: dict, db: Session = Depends(get_db),
            user=Depends(get_current_user)):
    """将策略对象转换为 YAML 文本（编辑器显示）。"""
    content = body.get("content")
    if not isinstance(content, dict):
        raise ValidationError("content 必须是对象")
    return {"text": svc.content_to_text(content)}


@router.get("/export")
def export_strategies(ids: Optional[str] = Query(None), db: Session = Depends(get_db),
                      user=Depends(get_current_user)):
    id_list = ids.split(",") if ids else None
    text = svc.export_strategies(db, id_list)
    return PlainTextResponse(text, media_type="text/yaml")


@router.get("/schema")
def strategy_schema():
    """策略 JSON Schema（运行时校验同样引用它，见 app/analysis/strategies.py）。"""
    import json
    from app.core.config import settings
    p = settings.strategy_dir / "schemas" / "strategy.schema.json"
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {}


@router.get("/meta")
def strategy_meta():
    return {
        "operators": available_operators(),
        "scopes": ["packet", "session", "host", "file", "correlation"],
        "severities": ["info", "low", "medium", "high", "critical"],
        "group_key_fields": sorted(GROUP_KEY_FIELDS),
        "fields": ALL_FIELDS_SORTED,
    }


def _detail(db: Session, strategy_id: str) -> StrategyDetail:
    row = svc.get_strategy(db, strategy_id)
    versions = svc.list_versions(db, strategy_id)
    return StrategyDetail(
        meta=_meta_out(row),
        versions=[StrategyVersionOut(id=v.id, strategy_id=v.strategy_id, version=v.version,
                                     status=v.status, published_by=v.published_by,
                                     published_at=v.published_at, created_at=v.created_at)
                  for v in versions],
        content=versions[0].content if versions else None,
    )


@router.get("/{strategy_id}", response_model=StrategyDetail)
def get_strategy(strategy_id: str, db: Session = Depends(get_db),
                 user=Depends(get_current_user)):
    return _detail(db, strategy_id)


@router.put("/{strategy_id}", response_model=StrategyDetail)
def update_strategy(strategy_id: str, body: StrategyUpsert, request: Request,
                    db: Session = Depends(get_db), user=Depends(get_current_user)):
    content = _resolve_content(body)
    svc.update_strategy_draft(db, strategy_id, content)
    if body.publish:
        svc.publish_version(db, strategy_id, username=user.username)
    if body.enabled is not None:
        svc.set_enabled(db, strategy_id, body.enabled)
    audit.log_audit(db, user_id=user.id, username=user.username, action="strategy.update",
                    target_type="strategy", target_id=strategy_id,
                    detail={"publish": body.publish}, ip=client_ip(request))
    db.commit()
    return _detail(db, strategy_id)


@router.post("/{strategy_id}/validate", response_model=ValidateResponse)
def validate(strategy_id: str, body: StrategyUpsert, db: Session = Depends(get_db),
             user=Depends(get_current_user)):
    content = _resolve_content(body)
    errors, warnings = validate_strategy(content)
    return ValidateResponse(valid=not errors, errors=errors, warnings=warnings)


@router.post("/{strategy_id}/publish", response_model=StrategyDetail)
def publish(strategy_id: str, request: Request, db: Session = Depends(get_db),
            user=Depends(get_current_user)):
    svc.publish_version(db, strategy_id, username=user.username)
    audit.log_audit(db, user_id=user.id, username=user.username, action="strategy.publish",
                    target_type="strategy", target_id=strategy_id, ip=client_ip(request))
    db.commit()
    return _detail(db, strategy_id)


@router.post("/{strategy_id}/enable", response_model=StrategyMetaOut)
def enable(strategy_id: str, request: Request, db: Session = Depends(get_db),
           user=Depends(get_current_user)):
    row = svc.set_enabled(db, strategy_id, True)
    audit.log_audit(db, user_id=user.id, username=user.username, action="strategy.enable",
                    target_type="strategy", target_id=strategy_id, ip=client_ip(request))
    db.commit()
    return _meta_out(row)


@router.post("/{strategy_id}/disable", response_model=StrategyMetaOut)
def disable(strategy_id: str, request: Request, db: Session = Depends(get_db),
            user=Depends(get_current_user)):
    row = svc.set_enabled(db, strategy_id, False)
    audit.log_audit(db, user_id=user.id, username=user.username, action="strategy.disable",
                    target_type="strategy", target_id=strategy_id, ip=client_ip(request))
    db.commit()
    return _meta_out(row)
