"""统一字段注册表（文档 8.3）。

引擎的 packet_values()（包级字段）与 sessions.values()（分组字段）是所有条件可引用字段的
唯一事实来源。策略校验、JSON Schema 与前端字段帮助共同引用本注册表，避免"拼错字段静默不命中"。

注意：分组求值时 session.* / host.* / file.* 别名对任意 scope 都会产出，因此条件字段
按"全部字段"校验（只拦拼写错误），不按 scope 收紧；window.group_by 才按分组键白名单校验。
"""
from __future__ import annotations

# --- 包级字段（engine.packet_values 产出） ---
PACKET_FIELDS = {
    "frame.number", "frame.time", "frame.length", "protocol",
    "ip.src", "ip.dst", "ip.proto", "eth.src", "eth.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.flags", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.rst",
    "tcp.flags.fin", "tcp.flags.push", "tcp.len", "tcp.payload_length",
    "tcp.payload_head", "udp.payload_length",
    "dns.query", "dns.qtype", "dns.qname_length", "dns.base_domain",
    "dns.rcode", "dns.response", "dns.answers",
    "http.method", "http.uri", "http.host", "http.user_agent",
    "http.response", "http.body_head", "http.status_code",
    "tls.version", "tls.sni", "tls.handshake_type",
    "icmp.type",
}

# --- 会话聚合字段（sessions.values 产出） ---
SESSION_FIELDS = {
    "session.count", "session.packet_count", "session.byte_count",
    "session.payload_bytes", "session.payload_ratio", "session.first_ts",
    "session.last_ts", "session.duration", "session.packet_rate",
    "session.avg_packet_size", "session.syn_count", "session.syn_only_count",
    "session.syn_pure_ratio", "session.synack_count", "session.ack_count",
    "session.rst_count", "session.fin_count",
    "session.completed_handshake_count", "session.handshake_completion_ratio",
    "session.rst_after_synack_count", "session.failed_connections",
    "session.distinct_dst_ports", "session.distinct_src_ports",
    "session.distinct_dst_ips", "session.distinct_src_ips",
    "session.dns_query_count", "session.dns_unique_queries",
    "session.dns_longest_query", "session.dns_entropy_max",
    "session.dns_nxdomain_count", "session.dns_nxdomain_ratio",
    "session.http_request_count", "session.tls_handshake_count",
    "session.tls_client_hello_count", "session.interval_mean_ms",
    "session.interval_stddev_ms", "session.periodicity_score",
    # 分组内的代表包字段
    "dns.query", "dns.query_length", "dns.base_domain",
    "ip.src", "ip.dst", "protocol", "tcp.srcport", "tcp.dstport",
    "tls.sni", "http.host", "http.uri", "http.method",
}

# --- 主机聚合字段 ---
HOST_FIELDS = {
    "host.ip", "host.packet_count", "host.bytes", "host.connections",
    "host.distinct_dst_ports", "host.distinct_dst_ips", "host.syn_count",
    "host.failed_connections", "host.failed_ratio", "host.dns_query_count",
    "host.nxdomain_ratio", "host.http_request_count", "host.tls_handshake_count",
    "host.payload_ratio", "host.duration", "host.packet_rate", "host.avg_packet_size",
}

# --- 文件聚合字段 ---
FILE_FIELDS = {
    "file.packet_count", "file.byte_count", "file.duration", "file.unique_ips",
    "file.unique_domains", "file.syn_count", "file.dns_query_count",
    "file.http_request_count", "file.tls_handshake_count", "file.encrypted_ratio",
    "file.payload_ratio", "file.avg_packet_size",
}

# 分组键（window.group_by 白名单，与 sessions._group_key_fn 保持一致）
GROUP_KEY_FIELDS = {
    "session.key", "ip.src", "ip.dst", "src_ip", "dst_ip",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "dns.base_domain", "http.host", "tls.sni",
}

# 全部可引用字段（union，供条件字段校验）
ALL_FIELDS = frozenset(PACKET_FIELDS | SESSION_FIELDS | HOST_FIELDS | FILE_FIELDS)

# 供前端"可用字段"帮助与 meta 接口展示
ALL_FIELDS_SORTED = sorted(ALL_FIELDS)


def is_supported_field(field: str) -> bool:
    return field in ALL_FIELDS
