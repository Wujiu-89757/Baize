"""单元测试：解析适配层（文档 12.2：损坏包、格式探测、容错）。"""
import pytest

from app.analysis.parsing.base import probe_format
from app.analysis.parsing.scapy_parser import parse_file
from tests.fixtures import gen


class TestFormatProbe:
    def test_pcap_magic(self, tmp_path):
        p = tmp_path / "a.pcap"
        p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 24)
        assert probe_format(str(p)) == "pcap"

    def test_pcap_nanosecond_magic(self, tmp_path):
        """纳秒时间戳 PCAP magic（两种字节序）也要识别为 pcap。"""
        for magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            p = tmp_path / "ns.pcap"
            p.write_bytes(magic + b"\x00" * 24)
            assert probe_format(str(p)) == "pcap", magic

    def test_pcapng_magic(self, tmp_path):
        p = tmp_path / "a.pcapng"
        p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 24)
        assert probe_format(str(p)) == "pcapng"

    def test_unknown_magic(self, tmp_path):
        p = tmp_path / "a.bin"
        p.write_bytes(b"MZ\x90\x00" + b"\x00" * 24)
        assert probe_format(str(p)) == "unknown"

    def test_short_file(self, tmp_path):
        p = tmp_path / "a.pcap"
        p.write_bytes(b"\x00\x00")
        assert probe_format(str(p)) == "unknown"


class TestParsing:
    def test_parse_normal(self, tmp_path):
        p = tmp_path / "n.pcap"
        gen.make_normal_pcap(str(p))
        records, stats = parse_file(str(p))
        assert stats.total_frames == 8
        assert stats.parsed_ok == 8
        protos = {r.protocol for r in records}
        assert "http" in protos and "dns" in protos and "tcp" in protos

    def test_http_metadata(self, tmp_path):
        p = tmp_path / "n.pcap"
        gen.make_normal_pcap(str(p))
        records, _ = parse_file(str(p))
        http_req = [r for r in records if r.http_method == "GET"]
        assert http_req and http_req[0].http_host == "www.example.com"
        http_resp = [r for r in records if r.http_status == 200]
        assert http_resp

    def test_dns_metadata(self, tmp_path):
        p = tmp_path / "n.pcap"
        gen.make_normal_pcap(str(p))
        records, _ = parse_file(str(p))
        queries = [r for r in records if r.dns_query == "www.example.com"]
        assert len(queries) == 2
        assert queries[0].dns_response is False
        assert queries[1].dns_response is True
        assert queries[1].dns_rcode == 0

    def test_scan_pcapng(self, tmp_path):
        p = tmp_path / "s.pcapng"
        gen.make_scan_pcap(str(p), n_ports=80)
        records, stats = parse_file(str(p))
        assert stats.total_frames == 8 + 80 * 2
        syns = [r for r in records if r.tcp_syn and not r.tcp_ack]
        assert len(syns) == 80

    def test_garbage_file_raises(self, tmp_path):
        p = tmp_path / "bad.pcap"
        p.write_bytes(b"not a pcap at all" * 10)
        with pytest.raises(ValueError):
            parse_file(str(p))

    def test_warning_not_crash(self, tmp_path):
        # 损坏的包（截断的以太网头）只记 warning 不崩溃
        from scapy.all import Ether, IP, TCP, wrpcap
        pkts = [Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=2, flags="S")]
        p = tmp_path / "t.pcap"
        wrpcap(str(p), pkts)
        with open(p, "ab") as fh:
            fh.write(b"\x00\x01\x02")  # 追加垃圾帧
        records, stats = parse_file(str(p))
        assert len(records) >= 1
