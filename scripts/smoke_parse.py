"""解析器冒烟测试：解析 111.pcapng 并输出统计。"""
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analysis.parsing.scapy_parser import parse_file  # noqa: E402

if __name__ == "__main__":
    sample = Path(__file__).resolve().parent.parent.parent / "111.pcapng"
    t0 = time.time()
    records, stats = parse_file(str(sample))
    t1 = time.time()
    print(f"frames: {stats.total_frames}  warnings: {stats.warnings}")
    print(f"first_ts: {stats.first_ts}  last_ts: {stats.last_ts}  time: {t1 - t0:.1f}s")
    c = Counter(r.protocol for r in records)
    print("protocols:", dict(c))
    syn = [r for r in records if r.tcp_syn and not r.tcp_ack]
    print("pure syn count:", len(syn))
    by_dst = defaultdict(lambda: [0, set()])
    for r in syn:
        by_dst[r.dst_ip][0] += 1
        by_dst[r.dst_ip][1].add(r.dst_port)
    for k, v in by_dst.items():
        print("dst", k, "syns", v[0], "ports", len(v[1]))
