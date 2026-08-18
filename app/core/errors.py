"""统一错误格式：{code, message, detail}。"""
from __future__ import annotations

from typing import Any


class AppError(Exception):
    """业务错误基类。"""

    status_code = 400
    code = "bad_request"

    def __init__(self, message: str = "", detail: Any = None):
        self.message = message or self.code
        self.detail = detail
        super().__init__(self.message)


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"


class AuthError(AppError):
    status_code = 401
    code = "unauthorized"


class ForbiddenError(AppError):
    status_code = 403
    code = "forbidden"


class ValidationError(AppError):
    status_code = 422
    code = "validation_error"


class ConflictError(AppError):
    status_code = 409
    code = "conflict"


class StrategyValidationError(ValidationError):
    """策略校验失败，detail 为错误列表。"""


class TaskStateError(AppError):
    code = "task_state_error"


def error_body(err: AppError, request_id: str) -> dict:
    return {
        "code": err.code,
        "message": err.message,
        "detail": err.detail,
        "request_id": request_id,
    }
