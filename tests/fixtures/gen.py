"""合成流量包夹具生成器（scapy）。"""
from __future__ import annotations

from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, TCP, UDP, conf
from scapy.packet import Raw
from scapy.utils import wrpcap, wrpcapng

conf.verb = 0  # 抑制 scapy 运行时噪声（getmacbyip 等）

_SRC_MAC = "11:22:33:44:55:66"
_DST_MAC = "aa:bb:cc:dd:ee:ff"


def _pkt(ts: float, *layers):
    p = layers[0]
    for l in layers[1:]:
        p = p / l
    p.time = ts
    return p


def _eth():
    return Ether(src=_SRC_MAC, dst=_DST_MAC)


def make_scan_pcap(path, n_ports: int = 150, src: str = "10.0.0.1",
                   dst: str = "10.0.0.2", base_ts: float = 1700000000.0) -> str:
    """正常 DNS + SYN 扫描 + RST 响应。"""
    pkts = []
    ts = base_ts
    for i in range(8):
        pkts.append(_pkt(ts + i * 0.01,
                         _eth(), IP(src="10.0.0.5", dst="8.8.8.8"),
                         UDP(sport=20000 + i, dport=53),
                         DNS(id=i, qr=0, qd=DNSQR(qname=f"www.example{i}.com"))))
    for port in range(n_ports):
        t = ts + 1 + port * 0.001
        pkts.append(_pkt(t, _eth(), IP(src=src, dst=dst),
                         TCP(sport=40000, dport=1000 + port, flags="S")))
        pkts.append(_pkt(t + 0.0005, _eth(), IP(src=dst, dst=src),
                         TCP(sport=1000 + port, dport=40000, flags="R")))
    wrpcapng(str(path), pkts)  # 写为 pcapng，覆盖 pcapng 解析路径
    return str(path)


def make_beacon_pcap(path, n: int = 8, interval: float = 5.0,
                     src: str = "10.0.0.7", dst: str = "203.0.113.9",
                     dport: int = 4444, base_ts: float = 1700000000.0) -> str:
    """周期性外连（Beacon）。"""
    pkts = []
    for i in range(n):
        t = base_ts + i * interval
        pkts.append(_pkt(t, _eth(), IP(src=src, dst=dst),
                         TCP(sport=50000, dport=dport, flags="S")))
        pkts.append(_pkt(t + 0.02, _eth(), IP(src=dst, dst=src),
                         TCP(sport=dport, dport=50000, flags="SA")))
    wrpcap(str(path), pkts)
    return str(path)


def make_normal_pcap(path, base_ts: float = 1700000000.0) -> str:
    """正常业务流量：HTTP、DNS、TLS。"""
    pkts = [
        _pkt(base_ts + 0.1, _eth(), IP(src="10.0.0.5", dst="10.0.0.6"),
             TCP(sport=12345, dport=80, flags="S")),
        _pkt(base_ts + 0.11, _eth(), IP(src="10.0.0.6", dst="10.0.0.5"),
             TCP(sport=80, dport=12345, flags="SA")),
        _pkt(base_ts + 0.12, _eth(), IP(src="10.0.0.5", dst="10.0.0.6"),
             TCP(sport=12345, dport=80, flags="A"),
             Raw(b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")),
        _pkt(base_ts + 0.13, _eth(), IP(src="10.0.0.6", dst="10.0.0.5"),
             TCP(sport=80, dport=12345, flags="PA"),
             Raw(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>")),
        _pkt(base_ts + 0.2, _eth(), IP(src="10.0.0.5", dst="8.8.8.8"),
             UDP(sport=20000, dport=53),
             DNS(id=1, qr=0, qd=DNSQR(qname="www.example.com"))),
        _pkt(base_ts + 0.21, _eth(), IP(src="8.8.8.8", dst="10.0.0.5"),
             UDP(sport=53, dport=20000),
             DNS(id=1, qr=1, qd=DNSQR(qname="www.example.com"),
                 an=DNSRR(rrname="www.example.com", rdata="93.184.216.34"))),
        _pkt(base_ts + 0.3, _eth(), IP(src="10.0.0.5", dst="10.0.0.6"),
             TCP(sport=12346, dport=443, flags="S")),
        _pkt(base_ts + 0.31, _eth(), IP(src="10.0.0.6", dst="10.0.0.5"),
             TCP(sport=443, dport=12346, flags="SA")),
    ]
    wrpcap(str(path), pkts)
    return str(path)


if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "fixtures"
    out.mkdir(exist_ok=True)
    make_scan_pcap(out / "syn_scan.pcapng")
    make_beacon_pcap(out / "beacon.pcap")
    make_normal_pcap(out / "normal.pcap")
    print("fixtures written to", out)
