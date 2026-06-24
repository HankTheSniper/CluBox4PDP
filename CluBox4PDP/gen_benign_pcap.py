#!/usr/bin/env python3
"""
gen_benign_pcap.py — Generate pure benign traffic PCAP for throughput testing.

Benign flow profile (same as gen_ddos_pcap.py):
  src: 10.1-4.x.x (200 unique IPs) → dst: 172.16.x.x (50 unique IPs)
  pkt_size: 64-1200 bytes, IAT: 5000-200000 us, TCP/UDP mixed
  PKT_COUNT=3 packets per flow

Output: /home/qcl306/dpdk/benign_only.pcap
        (~150,000 flows = 30 evaluation windows of 5000 flows)

Usage:
  python3 gen_benign_pcap.py [--flows 150000] [--out /path/to/output.pcap]
"""

import argparse
import struct
import socket
import random
import sys
import os

PKT_COUNT     = 3
SAMPLE_WINDOW = 5000

random.seed(42)

# ── Benign endpoints (same as gen_ddos_pcap.py) ────────────────────────────────

BENIGN_SRCS = [
    f"10.{a}.{b}.{c}"
    for a in (1, 2, 3, 4)
    for b in range(1, 11)
    for c in range(1, 6)
][:200]

BENIGN_DSTS = [
    f"172.16.{a}.{b}"
    for a in range(1, 3)
    for b in range(1, 26)
]

BENIGN_DPORTS = [80, 443, 8080, 53, 22, 3306, 25, 993, 587, 21]

# ── pcap format ────────────────────────────────────────────────────────────────

PCAP_GLOBAL_HDR = struct.pack('<IHHiIII',
    0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

ETH_HDR = b'\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x00'

# ── IP/transport helpers (identical to gen_ddos_pcap.py) ──────────────────────

def ip2int(s):
    return struct.unpack('!I', socket.inet_aton(s))[0]

BENIGN_SRC_INTS = [ip2int(ip) for ip in BENIGN_SRCS]
BENIGN_DST_INTS = [ip2int(ip) for ip in BENIGN_DSTS]

def _ip_hdr(src_int, dst_int, proto, total_ip_len):
    return struct.pack('!BBHHHBBH4s4s',
        0x45, 0, total_ip_len,
        random.randint(0, 65535),
        0, 64, proto, 0,
        struct.pack('!I', src_int),
        struct.pack('!I', dst_int),
    )

def build_udp(src_int, dst_int, sport, dport, frame_len):
    payload_len = max(0, frame_len - 14 - 20 - 8)
    udp_len     = 8 + payload_len
    ip          = _ip_hdr(src_int, dst_int, 17, 20 + udp_len)
    udp         = struct.pack('!HHHH', sport, dport, udp_len, 0)
    return ETH_HDR + ip + udp + bytes(payload_len)

def build_tcp(src_int, dst_int, sport, dport, frame_len):
    payload_len = max(0, frame_len - 14 - 20 - 20)
    ip  = _ip_hdr(src_int, dst_int, 6, 20 + 20 + payload_len)
    tcp = struct.pack('!HHIIBBHHH',
        sport, dport,
        random.randint(0, 0xFFFFFFFF), 0,
        0x50, 0x02, 65535, 0, 0)
    return ETH_HDR + ip + tcp + bytes(payload_len)

# ── Benign flow generator (identical to gen_ddos_pcap.py:benign_flow) ─────────

def benign_flow(start_ts):
    src_int = random.choice(BENIGN_SRC_INTS)
    dst_int = random.choice(BENIGN_DST_INTS)
    sport   = random.randint(1024, 65535)
    dport   = random.choice(BENIGN_DPORTS)
    proto   = random.choice([6, 17])
    max_pkt = random.randint(64, 1200)
    max_iat = random.randint(5_000, 200_000)

    builder = build_udp if proto == 17 else build_tcp
    pkts = []
    ts   = start_ts
    for i in range(PKT_COUNT):
        plen     = max_pkt if i == PKT_COUNT - 1 else random.randint(64, max_pkt)
        min_plen = 54 if proto == 6 else 64
        plen     = max(min_plen, plen)
        pkts.append((ts, builder(src_int, dst_int, sport, dport, plen)))
        if i < PKT_COUNT - 1:
            ts += random.randint(1_000, max_iat) * 1e-6
    return pkts

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate pure benign traffic PCAP for throughput testing")
    parser.add_argument("--flows", type=int, default=150_000,
                        help="Total number of benign flows (default: 150000 = 30 windows)")
    parser.add_argument("--out", default="/home/qcl306/dpdk/benign_only.pcap",
                        help="Output PCAP path")
    parser.add_argument("--interval-us", type=int, default=150,
                        help="Inter-flow start interval in µs (default: 150)")
    args = parser.parse_args()

    n_flows      = args.flows
    flow_gap_us  = args.interval_us
    output_path  = args.out

    print(f"Generating {n_flows:,} benign flows "
          f"(~{n_flows // SAMPLE_WINDOW} windows of {SAMPLE_WINDOW} flows)")
    print(f"Inter-flow gap: {flow_gap_us} µs")
    print(f"Output: {output_path}")
    print()

    base_ts  = 1704067200.0
    ts       = base_ts
    all_pkts = []

    report_every = max(1, n_flows // 10)
    for i in range(n_flows):
        all_pkts.extend(benign_flow(ts))
        ts += flow_gap_us * 1e-6
        if (i + 1) % report_every == 0:
            pct = (i + 1) * 100 // n_flows
            sys.stdout.write(f"\r  {pct}% ({i+1:,}/{n_flows:,} flows, "
                             f"{len(all_pkts):,} pkts)  ")
            sys.stdout.flush()

    print(f"\n\nTotal packets : {len(all_pkts):,}")
    print("Sorting ...", end=" ", flush=True)
    all_pkts.sort(key=lambda x: x[0])
    duration = all_pkts[-1][0] - all_pkts[0][0]
    print(f"done ({duration:.1f}s pcap duration)")

    print(f"Writing {output_path} ...", end=" ", flush=True)
    with open(output_path, 'wb') as f:
        f.write(PCAP_GLOBAL_HDR)
        for ts_f, pkt_bytes in all_pkts:
            ts_sec  = int(ts_f)
            ts_usec = int((ts_f - ts_sec) * 1_000_000)
            caplen  = len(pkt_bytes)
            f.write(struct.pack('<IIII', ts_sec, ts_usec, caplen, caplen))
            f.write(pkt_bytes)

    size_mb = os.path.getsize(output_path) / 1024 / 1024
    print(f"done ({size_mb:.1f} MB)")
    print()
    print("Next: rebuild without rate-limit, then run:")
    print(f"  cd /home/qcl306/dpdk/dpdk-22.11/examples/xpkt_clubox/build/")
    print(f"  meson configure -Dpcap_ratelimit=false .")
    print(f"  ninja")
    print(f"  sudo ./xpkt_clubox -l 0,1 \\")
    print(f"      --vdev 'eth_pcap0,rx_pcap={output_path}' --")
    print()
    print("Then plot:")
    print("  python3 plot_throughput_clubox.py <output_dir>")


if __name__ == "__main__":
    main()
