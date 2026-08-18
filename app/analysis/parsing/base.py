"""解析适配层：统一字段的数据包记录 + 解析器接口。

设计原则（文档 3/8.3）：
- 原始证据不可变，解析只读；
- 字段缺失必须为 None，不得随意填充；
- 单包解析失败只记 warning，不中断任务。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterator, Optional


@dataclass
class PacketRecord:
    """标准化数据包记录（统一字段，文档 8.3）。"""

    frame_number: int
    timestamp: float  # epoch 秒
    length: int
    link_type: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_proto: Optional[int] = None
    protocol: str = "other"          # tcp/udp/icmp/icmp6/arp/dns/http/tls/other（L7 分类）
    transport: Optional[str] = None  # tcp/udp/icmp/icmp6（传输层，用于流键与标志统计）
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    payload_length: int = 0
    # TCP
    tcp_flags: str = ""
    tcp_syn: bool = False
    tcp_ack: bool = False
    tcp_rst: bool = False
    tcp_fin: bool = False
    tcp_push: bool = False
    # DNS
    dns_query: Optional[str] = None
    dns_qtype: Optional[int] = None
    dns_response: Optional[bool] = None
    dns_rcode: Optional[int] = None
    dns_answers: Optional[int] = None
    dns_base_domain: Optional[str] = None
    dns_transaction_id: Optional[int] = None   # DNS 事务 ID（查询/响应配对用）
    # HTTP
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_host: Optional[str] = None
    http_user_agent: Optional[str] = None
    http_status: Optional[int] = None
    http_response: Optional[bool] = None
    # HTTP body 前缀（请求/响应体前若干字节，latin-1 文本化，用于载荷特征匹配）
    http_body_head: Optional[str] = None
    # 未识别为 HTTP/TLS/DNS 的 TCP 载荷前缀（头体分离的请求体等，用于 webshell 载荷匹配）
    tcp_payload_head: Optional[str] = None
    # TLS 元数据
    tls_version: Optional[str] = None
    tls_sni: Optional[str] = None
    tls_handshake_type: Optional[str] = None
    # ICMP
    icmp_type: Optional[int] = None
    # 其他
    parse_warnings: list = field(default_factory=list)

    def add_warning(self, msg: str) -> None:
        if len(self.parse_warnings) < 5:
            self.parse_warnings.append(msg)


@dataclass
class ParseStats:
    total_frames: int = 0
    parsed_ok: int = 0
    parse_failed: int = 0
    warnings: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    link_type: Optional[str] = None
    error: Optional[str] = None


class BaseParser(ABC):
    """解析器接口：迭代产生 PacketRecord。"""

    @abstractmethod
    def iter_packets(self, path: str, progress_cb=None) -> Iterator[PacketRecord]:
        """迭代解析。progress_cb(done, total) 可选。"""

    @property
    @abstractmethod
    def name(self) -> str:
        ...


def probe_format(path: str) -> str:
    """magic number 探测：pcap / pcapng / unknown（不信任扩展名，文档 7.2）。"""
    with open(path, "rb") as fh:
        magic = fh.read(4)
    if len(magic) < 4:
        return "unknown"
    if magic in (b"\x0a\x0d\x0d\x0a", b"\x0d\x0a\x0d\x0a"):  # pcapng (含字节序变体)
        return "pcapng"
    # pcap 微秒与纳秒时间戳 magic（两种字节序）
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                 b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return "pcap"
    return "unknown"
