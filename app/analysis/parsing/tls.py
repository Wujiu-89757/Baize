"""TLS 记录与 ClientHello SNI 提取（字节级、容错，文档 2.3：不解密、仅元数据）。"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

_TLS_TYPES = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data"}
_VERSION_MAP = {
    (3, 0): "SSLv3.0", (3, 1): "TLSv1.0", (3, 2): "TLSv1.1",
    (3, 3): "TLSv1.2", (3, 4): "TLSv1.3",
}
_HANDSHAKE_NAMES = {
    1: "client_hello", 2: "server_hello", 4: "new_session_ticket",
    11: "certificate", 12: "server_key_exchange", 13: "certificate_request",
    14: "server_hello_done", 15: "certificate_verify", 16: "client_key_exchange",
    20: "finished",
}
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-_.]{0,250})$")


@dataclass
class TlsInfo:
    version: Optional[str] = None
    handshake_type: Optional[str] = None
    sni: Optional[str] = None
    client_hello: bool = False


def _u16(b: bytes, off: int) -> Optional[int]:
    if off + 2 > len(b):
        return None
    return int.from_bytes(b[off:off + 2], "big")


def _extract_sni(client_hello: bytes) -> Optional[str]:
    """解析 ClientHello 的 SNI 扩展。任何不一致返回 None（容错）。"""
    try:
        if len(client_hello) < 38:
            return None
        off = 2 + 32                       # 跳过 legacy_version + random
        sid_len = client_hello[off]
        off += 1 + sid_len
        cipher_len = _u16(client_hello, off)
        if cipher_len is None:
            return None
        off += 2 + cipher_len
        if off >= len(client_hello):
            return None
        comp_len = client_hello[off]
        off += 1 + comp_len
        ext_total = _u16(client_hello, off)
        if ext_total is None or ext_total > len(client_hello) - off - 2:
            return None
        off += 2
        end = off + ext_total
        while off + 4 <= end:
            ext_type = _u16(client_hello, off)
            ext_len = _u16(client_hello, off + 2)
            off += 4
            if ext_type == 0 and ext_len >= 5 and off + ext_len <= end:
                sni_list_len = _u16(client_hello, off)
                if sni_list_len + 2 <= ext_len:
                    name_type = client_hello[off + 2]
                    name_len = _u16(client_hello, off + 3)
                    if name_type == 0 and name_len and off + 5 + name_len <= end:
                        raw = client_hello[off + 5: off + 5 + name_len]
                        try:
                            name = raw.decode("utf-8")
                        except UnicodeDecodeError:
                            return None
                        if _HOSTNAME_RE.match(name):
                            return name
                return None
            off += ext_len
    except (IndexError, ValueError):
        return None
    return None


def parse_tls(payload: bytes) -> TlsInfo:
    """从 TCP 载荷解析 TLS 记录元数据。"""
    info = TlsInfo()
    if len(payload) < 5 or payload[0] not in _TLS_TYPES or payload[1] != 0x03:
        return info
    rtype = payload[0]
    version = _VERSION_MAP.get((payload[1], payload[2]))
    rec_len = int.from_bytes(payload[3:5], "big")
    info.version = version or f"0x{payload[1]:02x}{payload[2]:02x}"
    if rtype != 22:  # 非 handshake 记录
        return info
    if rec_len + 5 > len(payload):
        return info
    body = payload[5:5 + rec_len]
    if not body:
        return info
    htype = body[0]
    info.handshake_type = _HANDSHAKE_NAMES.get(htype, f"handshake_{htype}")
    if htype == 1:
        info.client_hello = True
        info.sni = _extract_sni(body)
    return info
