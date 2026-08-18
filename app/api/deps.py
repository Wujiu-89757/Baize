"""API 依赖：数据库会话与本地操作上下文。

本地免登录模式：无用户/权限概念，所有请求直接进入系统。
get_current_user 返回固定的本地操作上下文（审计主体固定为"本地"）。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fastapi import Request

from app.db import db_session


@dataclass(frozen=True)
class LocalOperator:
    """本地操作上下文（替代已删除的用户模型）。"""
    id: Optional[int] = None
    username: str = "本地"
    display_name: str = "本地模式"


def get_db():
    with db_session() as session:
        yield session


def get_current_user() -> LocalOperator:
    """本地模式：直接返回本地操作上下文（不校验任何令牌/身份）。"""
    return LocalOperator()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""
