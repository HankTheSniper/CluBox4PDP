#!/usr/bin/env python3
"""
gen_ddos_pcap.py — Generate DDoS simulation PCAP for xpkt_clubox.

Two modes:

  --mode single (default)
    Single-source UDP flooding: src=192.168.50.1, dst=10.0.0.100.
    Poseidon and Jaqen detect this trivially via heavy-hitter (one IP = 65% of traffic).
    Output: /home/qcl306/dpdk/ddos_sim.pcap

  --mode distributed
    Distributed DDoS with IP spoofing:
      - 50,000 unique random spoofed source IPs (no heavy-hitter source)
      - 200 victim IPs in 192.168.100.0/24 (no heavy-hitter destination)
    Poseidon and Jaqen both fail (no single-IP heavy hitter exists).
    xpkt_clubox still detects via flow features: large packets + low IAT.
    Output: /home/qcl306/dpdk/ddos_distributed.pcap

Attack feature profile (both modes — same flow characteristics):
  pkt_size: 1100-1440 bytes (UDP amplification)
  inter-packet IAT: 50-800 us

Benign profile (same in both modes):
  src=10.x.x.x -> dst=172.16.x.x, TCP/UDP mixed
  pkt_size: 64-1200 bytes, IAT: 5000-200000 us

Phase design (~30 evaluation windows of 5000 flows):
  1. Benign stable      (6 windows,  0% attack)
  2. Attack ramp-up     (3 windows, 20/45/60% attack)
  3. Mixed attack       (10 windows, 65% attack)
  4. Attack taper       (3 windows, 45/20/5% attack)
  5. Benign recovery    (7 windows,  0% attack)
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

# ── Benign endpoints ───────────────────────────────────────────────────────────

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

# ── Distributed mode attack endpoints ─────────────────────────────────────────

# 200 victim IPs each in a DIFFERENT /24 subnet (198.b.c.100 with unique (b,c)).
# This defeats ACC-Turbo's destination-prefix aggregation:
#   each dst /24 gets only 65%/200 ≈ 0.3% of flows — far below any rate threshold.
DIST_VICTIM_IPS = [
    f"198.{1 + i // 20}.{(i % 20) * 5 + 1}.100"
    for i in range(200)
]
# Results in /24 prefixes: 198.1.1.0/24, 198.1.6.0/24, ..., 198.10.96.0/24 (200 unique)

# 50,000 random internet IPs for spoofed sources (pre-computed pool).
# Exclude RFC-1918 private ranges AND 198.x (reserved for victims above).
def _random_public_ip():
    while True:
        a = random.randint(1, 223)
        if a in (10, 172, 192, 198):
            continue
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        return f"{a}.{b}.{c}.{d}"

SPOOFED_SRC_POOL = [_random_public_ip() for _ in range(50_000)]

# ── pcap format ────────────────────────────────────────────────────────────────

PCAP_GLOBAL_HDR = struct.pack('<IHHiIII',
    0xa1b2c3d4,   # magic (microsecond timestamps)
    2, 4,
    0, 0,
    65535,
    1             # data link type: Ethernet
)

ETH_HDR = b'\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x00'

# ── IP helpers ─────────────────────────────────────────────────────────────────

def ip2int(s):
    return struct.unpack('!I', socket.inet_aton(s))[0]

BENIGN_SRC_INTS  = [ip2int(ip) for ip in BENIGN_SRCS]
BENIGN_DST_INTS  = [ip2int(ip) for ip in BENIGN_DSTS]
DIST_VICTIM_INTS = [ip2int(ip) for ip in DIST_VICTIM_IPS]
SPOOFED_SRC_INTS = [ip2int(ip) for ip in SPOOFED_SRC_POOL]

# ── Packet builders ────────────────────────────────────────────────────────────

def _ip_hdr(src_int, dst_int, proto, total_ip_len):
    return struct.pack('!BBHHHBBH4s4s',
        0x45, 0,
        total_ip_len,
        random.randint(0, 65535),
        0, 64, proto, 0,
        struct.pack('!I', src_int),
        struct.pack('!I', dst_int),
    )

def build_udp(src_int, dst_int, sport, dport, frame_len):
    payload_len = max(0, frame_len - 14 - 20 - 8)
    udp_len     = 8 + payload_len
    ip_total    = 20 + udp_len
    ip  = _ip_hdr(src_int, dst_int, 17, ip_total)
    udp = struct.pack('!HHHH', sport, dport, udp_len, 0)
    return ETH_HDR + ip + udp + bytes(payload_len)

def build_tcp(src_int, dst_int, sport, dport, frame_len):
    payload_len = max(0, frame_len - 14 - 20 - 20)
    ip_total    = 20 + 20 + payload_len
    ip  = _ip_hdr(src_int, dst_int, 6, ip_total)
    tcp = struct.pack('!HHIIBBHHH',
        sport, dport,
        random.randint(0, 0xFFFFFFFF), 0,
        0x50, 0x02, 65535, 0, 0
    )
    return ETH_HDR + ip + tcp + bytes(payload_len)

# ── Flow generators ────────────────────────────────────────────────────────────

def attack_flow_single(start_ts):
    """Fixed-source attack: 192.168.50.1 → 10.0.0.100. Easy for heavy-hitter detection."""
    atk_src = ip2int("192.168.50.1")
    atk_dst = ip2int("10.0.0.100")
    sport    = random.randint(1024, 65535)
    dport    = random.choice([53, 80, 443, 123, 19])
    max_pkt  = random.randint(1100, 1440)
    max_iat  = random.randint(50, 800)

    pkts = []
    ts   = start_ts
    for i in range(PKT_COUNT):
        plen = max_pkt if i == PKT_COUNT - 1 else random.randint(max_pkt - 200, max_pkt)
        plen = max(64, plen)
        pkts.append((ts, build_udp(atk_src, atk_dst, sport, dport, plen)))
        if i < PKT_COUNT - 1:
            ts += random.randint(10, max_iat) * 1e-6
    return pkts


def attack_flow_distributed(start_ts):
    """
    Distributed spoofed-source attack:
      - Source IP: random from 50k-IP public pool (no heavy hitter)
      - Destination: random victim from 200 IPs in 192.168.100.0/24 (no heavy hitter)
      - Same attack features: large packets (1100-1440B), low IAT (50-800µs)
    Poseidon and Jaqen both fail; xpkt_clubox detects via feature cluster.
    """
    src_int = random.choice(SPOOFED_SRC_INTS)
    dst_int = random.choice(DIST_VICTIM_INTS)
    sport   = random.randint(1024, 65535)
    dport   = random.choice([53, 80, 443, 123, 19])
    max_pkt = random.randint(1100, 1440)
    max_iat = random.randint(50, 800)

    pkts = []
    ts   = start_ts
    for i in range(PKT_COUNT):
        plen = max_pkt if i == PKT_COUNT - 1 else random.randint(max_pkt - 200, max_pkt)
        plen = max(64, plen)
        pkts.append((ts, build_udp(src_int, dst_int, sport, dport, plen)))
        if i < PKT_COUNT - 1:
            ts += random.randint(10, max_iat) * 1e-6
    return pkts


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
        plen = max_pkt if i == PKT_COUNT - 1 else random.randint(64, max_pkt)
        min_plen = 54 if proto == 6 else 64
        plen = max(min_plen, plen)
        pkts.append((ts, builder(src_int, dst_int, sport, dport, plen)))
        if i < PKT_COUNT - 1:
            ts += random.randint(1_000, max_iat) * 1e-6
    return pkts

# ── Phase engine ──────────────────────────────────────────────────────────────

def gen_phase(n_flows, atk_ratio, start_ts, flow_interval_us, atk_fn):
    pkts  = []
    ts    = start_ts
    n_atk = 0
    n_ben = 0
    for _ in range(n_flows):
        if random.random() < atk_ratio:
            pkts.extend(atk_fn(ts))
            n_atk += 1
        else:
            pkts.extend(benign_flow(ts))
            n_ben += 1
        ts += flow_interval_us * 1e-6
    return pkts, ts, n_atk, n_ben

# ── Phase definition ──────────────────────────────────────────────────────────
# ~30 evaluation windows of 5000 flows each

PHASES = [
    ("Benign stable",    30_000, 0.00, 150),
    ("Attack ramp-up",    5_000, 0.20, 120),
    ("Attack ramp-up",    5_000, 0.45, 110),
    ("Attack ramp-up",    5_000, 0.60, 100),
    ("Mixed attack",     50_000, 0.65,  80),
    ("Attack taper",      5_000, 0.45, 100),
    ("Attack taper",      5_000, 0.20, 120),
    ("Attack taper",      5_000, 0.05, 140),
    ("Benign recovery",  35_000, 0.00, 150),
]

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate DDoS simulation PCAP")
    parser.add_argument(
        "--mode", choices=["single", "distributed"], default="single",
        help="single: fixed-IP attack (Poseidon/Jaqen trivially detect); "
             "distributed: spoofed sources + many victims (only xpkt_clubox detects)")
    args = parser.parse_args()

    if args.mode == "single":
        output_path = "/home/qcl306/dpdk/ddos_sim.pcap"
        atk_fn      = attack_flow_single
        atk_label   = "fixed src=192.168.50.1 → dst=10.0.0.100"
        gt_note      = "ground truth: endpoint == 192.168.50.1"
    else:
        output_path = "/home/qcl306/dpdk/ddos_distributed.pcap"
        atk_fn      = attack_flow_distributed
        atk_label   = "50k spoofed sources → 200 victims across 200 different /24 subnets (198.x.x.x)"
        gt_note      = "ground truth: either endpoint starts with '198.'"

    total_flows = sum(p[1] for p in PHASES)
    print(f"Mode: {args.mode}")
    print(f"Attack: {atk_label}")
    print(f"Output: {output_path}")
    print(f"Phases: {len(PHASES)} | Flows: {total_flows} "
          f"(~{total_flows // SAMPLE_WINDOW} windows)")
    print()

    base_ts  = 1704067200.0
    all_pkts = []
    ts       = base_ts

    for name, n_flows, atk_ratio, fiu in PHASES:
        sys.stdout.write(f"  [{name}] {n_flows} flows, {atk_ratio:.0%} attack ... ")
        sys.stdout.flush()
        pkts, ts, n_atk, n_ben = gen_phase(n_flows, atk_ratio, ts, fiu, atk_fn)
        all_pkts.extend(pkts)
        print(f"{len(pkts)} pkts (atk={n_atk} ben={n_ben})")

    print(f"\nTotal packets: {len(all_pkts):,}")
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
    print(f"\n{gt_note}")
    print()
    print("Next steps:")
    print(f"  sudo build/xpkt_clubox -l 0,1 \\")
    print(f"      --vdev 'eth_pcap0,rx_pcap={output_path}' --")
    print()
    print(f"Then compare:")
    if args.mode == "single":
        print("  python3 compare_baselines.py output_YYYYMMDD_HHMMSS --mode single --plot")
    else:
        print("  python3 compare_baselines.py output_YYYYMMDD_HHMMSS --mode distributed --plot")
    print()
    print("Expected windows (~30 total):")
    print("  1-6:   benign stable  (TP=0, TN=5000)")
    print("  7-9:   ramp-up       (TP rises)")
    print("  10-19: sustained 65% (TP~3250)")
    print("  20-22: taper         (TP falls)")
    print("  23-29: recovery      (TP=0, TN=5000)")


if __name__ == "__main__":
    main()
