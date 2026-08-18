"""HTTP 元数据解析（字节级，无需 TCP 重组即可提取首个请求/响应头）。"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
_REQ_LINE = re.compile(rb"^([A-Z]+)\s+(\S+)\s+HTTP/\d(?:\.\d)?\r?\n", re.I)
_RES_LINE = re.compile(rb"^HTTP/\d(?:\.\d)?\s+(\d{3})[^\r\n]*\r?\n", re.I)
_HEADER = re.compile(rb"^([!#$%&'*+\-.^_`|~0-9A-Za-z]+):\s*([^\r\n]*)\r?\n", re.I | re.M)
_LINE_LIMIT = 64 * 1024  # 单行上限
_BODY_HEAD_LEN = 256  # 请求/响应体前缀截取长度（用于载荷特征匹配，如 webshell 密文前缀）


@dataclass
class HttpInfo:
    method: Optional[str] = None
    uri: Optional[str] = None
    status: Optional[int] = None
    host: Optional[str] = None
    user_agent: Optional[str] = None
    response: Optional[bool] = None
    body_head: Optional[str] = None

    @property
    def is_http(self) -> bool:
        return self.method is not None or self.status is not None


def _decode(b: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode("utf-8", errors="replace")


def parse_http(payload: bytes) -> HttpInfo:
    """解析 TCP 载荷中的首个 HTTP 请求/响应（不做流重组）。"""
    info = HttpInfo()
    if not payload:
        return info
    head = payload[: _LINE_LIMIT]
    m = _REQ_LINE.match(head)
    if m and m.group(1).decode("ascii", errors="ignore").upper() in _METHODS:
        info.method = _decode(m.group(1)).upper()
        info.uri = _decode(m.group(2))[:500]
        info.response = False
        rest = head[m.end():]
    else:
        m = _RES_LINE.match(head)
        if not m:
            return info
        info.status = int(m.group(1))
        info.response = True
        rest = head[m.end():]

    for hm in _HEADER.finditer(rest):
        name = _decode(hm.group(1)).lower()
        val = _decode(hm.group(2)).strip()
        if name == "host" and info.host is None:
            info.host = val[:255]
        elif name in ("user-agent", "user_agent") and info.user_agent is None:
            info.user_agent = val[:255]

    # 请求/响应体前缀（首个 \r\n\r\n 之后的原始字节，不做重组；latin-1 保证无解码失败）
    idx = rest.find(b"\r\n\r\n")
    if idx != -1:
        body = rest[idx + 4: idx + 4 + _BODY_HEAD_LEN]
        if body:
            info.body_head = body.decode("latin-1")
    return info
