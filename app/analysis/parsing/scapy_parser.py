"""scapy 解析后端：pcap/pcapng → 统一 PacketRecord。"""
from __future__ import annotations

import os
from typing import Callable, Iterator, Optional

from scapy.layers.all import ARP, DNS, ICMP, ICMPv6EchoReply, ICMPv6EchoRequest, IP, IPv6, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import ICMPv6Unknown
from scapy.packet import Raw
from scapy.utils import PcapNgReader, PcapReader

from app.analysis.parsing.base import BaseParser, PacketRecord, ParseStats, probe_format
from app.analysis.parsing.http import parse_http
from app.analysis.parsing.tls import parse_tls
from app.core.logging import get_logger

log = get_logger("baize.parser")

# 常见链路类型（IEEE 注册号）
_LINK_ETHERNET = 1
_LINK_RAW_IP = 101
_LINK_LINUX_SLL = 113
_LINK_IPV4 = 228
_LINK_IPV6 = 229
_LINK_LINUX_SLL2 = 276

_TCP_FLAG_BITS = (("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08),
                  ("A", 0x10), ("U", 0x20), ("E", 0x40), ("C", 0x80))


def _flags_str(flags: int) -> str:
    return "".join(name for name, bit in _TCP_FLAG_BITS if flags & bit)


def _dissect_sll(raw: bytes):
    """scapy 2.7 无 SLL 层类，手动解析 Linux cooked capture (linktype 113)。"""
    if len(raw) < 16:
        return None
    proto = int.from_bytes(raw[14:16], "big")
    payload = raw[16:]
    if proto == 0x0800:
        return IP(payload)
    if proto == 0x86DD:
        return IPv6(payload)
    try:
        return Ether(payload)
    except Exception:  # noqa: BLE001
        return None


def base_domain(query: str) -> str:
    """启发式注册域：取最后两个标签。v0.1 不引入公共后缀表。"""
    q = query.rstrip(".").lower()
    labels = q.split(".")
    if len(labels) >= 3:
        return ".".join(labels[-2:])
    return q


class ScapyParser(BaseParser):
    name = "scapy"

    def iter_packets(self, path: str, progress_cb: Optional[Callable[[int, int], None]] = None) -> Iterator[PacketRecord]:
        fmt = probe_format(path)
        total = os.path.getsize(path)
        done = 0
        if fmt == "pcapng":
            yield from self._iter_pcapng(path, total, done, progress_cb)
        elif fmt == "pcap":
            yield from self._iter_pcap(path, total, progress_cb)
        else:
            raise ValueError(f"不支持的流量包格式（magic 探测失败）: {path}")

    # --------------------------------------------------------------
    def _iter_pcapng(self, path: str, total: int, done: int, progress_cb) -> Iterator[PacketRecord]:
        reader = PcapNgReader(path)
        for frame_no, pkt in enumerate(reader, start=1):
            raw = bytes(pkt)
            ts = float(getattr(pkt, "time", 0.0) or 0.0)  # scapy pcapng 时间可能是 Decimal
            record = self._dissect(frame_no, ts, raw)
            done += len(raw)
            if progress_cb and done % 1_000_000 < len(raw):
                progress_cb(min(99, int(done * 100 / max(total, 1))), total)
            yield record
        if progress_cb:
            progress_cb(100, total)

    def _iter_pcap(self, path: str, total: int, progress_cb) -> Iterator[PacketRecord]:
        reader = PcapReader(path)
        linktype = getattr(reader, "linktype", _LINK_ETHERNET)
        for frame_no, pkt in enumerate(reader, start=1):
            ts = float(getattr(pkt, "time", 0.0) or 0.0)
            record = self._dissect(frame_no, ts, bytes(pkt), linktype_hint=linktype)
            done = reader.f.tell() if getattr(reader, "f", None) else (frame_no * 64)
            if progress_cb:
                progress_cb(min(99, int(done * 100 / max(total, 1))), total)
            yield record
        if progress_cb:
            progress_cb(100, total)

    # --------------------------------------------------------------
    def _dissect(self, frame_no: int, ts: float, raw: bytes, linktype_hint: Optional[int] = None) -> PacketRecord:
        rec = PacketRecord(frame_number=frame_no, timestamp=ts, length=len(raw))
        rec.link_type = self._link_type_name(linktype_hint)
        try:
            pkt = self._link_dissect(raw, linktype_hint)
        except Exception as exc:  # noqa: BLE001
            rec.protocol = "other"
            rec.add_warning(f"链路层解析失败: {type(exc).__name__}")
            return rec
        if pkt is None:
            rec.add_warning("无法识别链路层类型")
            return rec
        self._extract(rec, pkt)
        return rec

    @staticmethod
    def _link_dissect(raw: bytes, linktype_hint: Optional[int] = None):
        if linktype_hint == _LINK_RAW_IP or linktype_hint in (_LINK_IPV4, _LINK_IPV6):
            return IP(raw) if linktype_hint != _LINK_IPV6 else IPv6(raw)
        if linktype_hint == _LINK_LINUX_SLL:
            return _dissect_sll(raw)
        if linktype_hint == _LINK_LINUX_SLL2:
            # SLL2 头部 20 字节：协议字段在偏移 0~1（字节序依赖抓包机，按 0x0800 常见值尝试）
            try:
                if len(raw) >= 20:
                    proto = int.from_bytes(raw[0:2], "big")
                    payload = raw[20:]
                    if proto == 0x0800:
                        return IP(payload)
                    if proto == 0x86DD:
                        return IPv6(payload)
            except Exception:  # noqa: BLE001
                pass
            try:
                return Ether(raw)
            except Exception:  # noqa: BLE001
                return None
        try:
            return Ether(raw)
        except Exception:  # noqa: BLE001
            try:
                return IP(raw)
            except Exception:  # noqa: BLE001
                try:
                    return IPv6(raw)
                except Exception:  # noqa: BLE001
                    return None

    @staticmethod
    def _link_type_name(linktype_hint: Optional[int]) -> str:
        """链路类型展示名（写入 PacketRecord.link_type / ParseStats.link_type）。"""
        if linktype_hint == _LINK_LINUX_SLL:
            return "linux_sll"
        if linktype_hint == _LINK_LINUX_SLL2:
            return "linux_sll2"
        if linktype_hint in (_LINK_RAW_IP, _LINK_IPV4, _LINK_IPV6):
            return "raw_ip"
        return "ethernet"

    # --------------------------------------------------------------
    def _extract(self, rec: PacketRecord, pkt) -> None:
        # ARP
        if ARP in pkt:
            rec.protocol = "arp"
            rec.src_ip = pkt[ARP].psrc
            rec.dst_ip = pkt[ARP].pdst
            rec.src_mac = pkt[ARP].hwsrc
            rec.dst_mac = pkt[ARP].hwdst
            return

        # 以太网 MAC
        if Ether in pkt:
            rec.src_mac = pkt[Ether].src
            rec.dst_mac = pkt[Ether].dst

        # 网络层
        if IP in pkt:
            rec.src_ip = pkt[IP].src
            rec.dst_ip = pkt[IP].dst
            rec.ip_proto = int(pkt[IP].proto)
        elif IPv6 in pkt:
            rec.src_ip = pkt[IPv6].src
            rec.dst_ip = pkt[IPv6].dst
            rec.ip_proto = int(pkt[IPv6].nh)

        # ICMP
        if ICMP in pkt:
            rec.protocol = "icmp"
            rec.icmp_type = int(pkt[ICMP].type)
            rec.payload_length = self._payload_len(pkt)
            return
        if ICMPv6EchoRequest in pkt or ICMPv6EchoReply in pkt or ICMPv6Unknown in pkt:
            rec.protocol = "icmp6"
            rec.payload_length = self._payload_len(pkt)
            return

        # 传输层
        if TCP in pkt:
            tcp = pkt[TCP]
            rec.protocol = "tcp"
            rec.transport = "tcp"
            rec.src_port = int(tcp.sport)
            rec.dst_port = int(tcp.dport)
            flags = int(tcp.flags)
            rec.tcp_flags = _flags_str(flags)
            rec.tcp_syn = bool(flags & 0x02)
            rec.tcp_ack = bool(flags & 0x10)
            rec.tcp_rst = bool(flags & 0x04)
            rec.tcp_fin = bool(flags & 0x01)
            rec.tcp_push = bool(flags & 0x08)
            rec.payload_length = self._payload_len(pkt)
            self._extract_l7_tcp(rec, pkt)
        elif UDP in pkt:
            udp = pkt[UDP]
            rec.protocol = "udp"
            rec.transport = "udp"
            rec.src_port = int(udp.sport)
            rec.dst_port = int(udp.dport)
            rec.payload_length = self._payload_len(pkt)
            self._extract_dns(rec, pkt, tcp=False)
        else:
            rec.payload_length = self._payload_len(pkt)

    @staticmethod
    def _payload_len(pkt) -> int:
        if Raw in pkt:
            return len(bytes(pkt[Raw]))
        return 0

    # --------------------------------------------------------------
    def _extract_l7_tcp(self, rec: PacketRecord, pkt) -> None:
        payload = bytes(pkt[TCP].payload) if Raw in pkt else b""
        if not payload:
            return
        if rec.dst_port == 53 or rec.src_port == 53:
            self._extract_dns(rec, pkt, tcp=True, payload=payload)
            return
        http = parse_http(payload)
        if http.is_http:
            rec.protocol = "http"
            rec.http_method = http.method
            rec.http_uri = http.uri
            rec.http_host = http.host
            rec.http_user_agent = http.user_agent
            rec.http_status = http.status
            rec.http_response = http.response
            rec.http_body_head = http.body_head
            return
        tls = parse_tls(payload)
        if tls.version is not None:
            rec.protocol = "tls"
            rec.tls_version = tls.version
            rec.tls_handshake_type = tls.handshake_type
            rec.tls_sni = tls.sni
            return
        # 非 HTTP/TLS 的 TCP 载荷：保留前缀供载荷特征匹配
        # （如 HTTP 头体分离时后续段中的请求体、webshell 密文等）
        rec.tcp_payload_head = payload[:256].decode("latin-1")

    def _extract_dns(self, rec: PacketRecord, pkt, tcp: bool = False, payload: bytes = b"") -> None:
        try:
            if tcp:
                if len(payload) < 2:
                    return
                dns = DNS(payload[2:])
            else:
                if DNS not in pkt:
                    return
                dns = pkt[DNS]
            if dns is None or not hasattr(dns, "qd") or not dns.qd:
                return
            rec.protocol = "dns"
            rec.dns_response = bool(int(dns.qr))
            rec.dns_rcode = int(dns.rcode) if dns.rcode is not None else None
            rec.dns_answers = len(dns.an) if dns.an else 0
            rec.dns_transaction_id = int(dns.id) if getattr(dns, "id", None) is not None else None
            q = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
            if q is not None and getattr(q, "qname", None):
                name = bytes(q.qname).decode("utf-8", errors="replace").rstrip(".")
                rec.dns_query = name[:255]
                rec.dns_qtype = int(q.qtype) if q.qtype is not None else None
                rec.dns_base_domain = base_domain(name)
        except Exception as exc:  # noqa: BLE001
            rec.add_warning(f"DNS 解析失败: {type(exc).__name__}")


def parse_file(path: str, progress_cb=None) -> tuple[list[PacketRecord], ParseStats]:
    """便捷入口：完整解析一个文件，返回记录列表与统计。"""
    stats = ParseStats()
    parser = ScapyParser()
    records: list[PacketRecord] = []
    try:
        for rec in parser.iter_packets(path, progress_cb):
            stats.total_frames += 1
            if rec.parse_warnings:
                stats.warnings += len(rec.parse_warnings)
            if stats.first_ts is None or rec.timestamp < stats.first_ts:
                stats.first_ts = rec.timestamp
            if stats.last_ts is None or rec.timestamp > stats.last_ts:
                stats.last_ts = rec.timestamp
            records.append(rec)
    except Exception as exc:  # noqa: BLE001
        stats.error = str(exc)
        raise
    stats.parsed_ok = len(records)
    if records and records[0].link_type:
        stats.link_type = records[0].link_type
    return records, stats
