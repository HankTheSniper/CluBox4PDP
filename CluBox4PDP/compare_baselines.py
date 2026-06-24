#!/usr/bin/env python3
"""
compare_baselines.py — Per-window comparison of four DDoS detection systems.

Systems compared
────────────────
  xpkt_clubox   Feature-based online clustering (CluBox) + DT + LR.
                Detects attacks via flow behavioral features (pkt_size, IAT).
                Not dependent on IP identity → robust to spoofing.

  Poseidon      (NDSS 2020) Source-IP heavy-hitter detection.
                Ingress monitoring: counts flows per source IP.
                Fails when sources are spoofed/distributed.

  Jaqen         (USENIX Security 2021) Multi-sketch bidirectional analysis.
                Detects source AND destination heavy-hitters + fan-out check.
                Partially robust to spoofing (victim detection), but fails
                when no single destination exceeds threshold.

  ACC-Turbo     (SIGCOMM 2022) Aggregate-based congestion control.
                Groups flows by destination /24 prefix + protocol (traffic aggregate).
                Detects aggregates with anomalously high flow rates.
                Fails when victims are spread across many different /24 subnets.

Evaluation modes
────────────────
  --mode single        Fixed-IP attack (192.168.50.1 → 10.0.0.100).
                       Ground truth: either endpoint == 192.168.50.1.
                       All four systems expected to detect.

  --mode distributed   Distributed DDoS: 50k spoofed sources →
                       200 victims in 200 different /24 subnets (198.x.x.x).
                       Ground truth: either endpoint starts with "198.".
                       Only xpkt_clubox expected to detect.

Usage:
  python3 compare_baselines.py <output_dir> [--mode single|distributed] [--plot]
"""

import argparse
import glob
import os
import sys
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

SAMPLE_WINDOW = 5000


# ── Ground truth ──────────────────────────────────────────────────────────────

def make_gt_fn(mode: str):
    if mode == "single":
        ATTACK_IP = "192.168.50.1"
        def gt(src, dst):
            return int(src == ATTACK_IP or dst == ATTACK_IP)
    else:
        # Distributed: victims in 198.x.x.x (200 different /24 subnets)
        def gt(src, dst):
            return int(src.startswith("198.") or dst.startswith("198."))
    return gt


# ── Poseidon (NDSS 2020) ──────────────────────────────────────────────────────

def poseidon_predict(df: pd.DataFrame, k: float = 3.0) -> np.ndarray:
    """
    Source-IP-only heavy-hitter detection (ingress monitoring model).
    Flows from source IPs with count > mean + k*std → predicted attack.
    Fails in distributed mode: 50k unique sources, each appears ~0.002%.
    """
    src_counts = Counter(df["src_ip"])
    counts = np.array(list(src_counts.values()), dtype=float)
    threshold = counts.mean() + k * counts.std()
    heavy_srcs = {ip for ip, cnt in src_counts.items() if cnt > threshold}
    return np.array(
        [1 if r.src_ip in heavy_srcs else 0
         for r in df.itertuples(index=False)],
        dtype=int,
    )


# ── Jaqen (USENIX Security 2021) ─────────────────────────────────────────────

def jaqen_predict(df: pd.DataFrame, top_k: int = 3,
                   fanout_thresh: float = 0.1) -> np.ndarray:
    """
    Bidirectional heavy-hitter: source HH + destination HH (victim detection).
    Fan-out concentration check: attacker hitting few unique destinations.
    Fails in distributed mode: 200 victims each <0.5% of flows, no single HH dst.
    """
    src_counts = Counter(df["src_ip"])
    dst_counts = Counter(df["dst_ip"])
    top_src_ips = {ip for ip, _ in src_counts.most_common(top_k)}
    top_dst_ips = {ip for ip, _ in dst_counts.most_common(top_k)}

    src_to_dsts: defaultdict = defaultdict(set)
    for src, dst in zip(df["src_ip"], df["dst_ip"]):
        src_to_dsts[src].add(dst)

    attack_ips: set = set()
    for src in top_src_ips:
        dsts        = src_to_dsts[src]
        fanout      = len(dsts) / max(src_counts[src], 1)
        hits_victim = bool(dsts & top_dst_ips)
        concentrated = fanout < fanout_thresh
        if hits_victim or concentrated:
            attack_ips.add(src)
            attack_ips.update(dsts)

    return np.array(
        [1 if (r.src_ip in attack_ips or r.dst_ip in attack_ips) else 0
         for r in df.itertuples(index=False)],
        dtype=int,
    )


# ── ACC-Turbo (SIGCOMM 2022) ──────────────────────────────────────────────────

_ACC_TURBO_STATE: list = []   # persistent cluster state across windows


def acc_turbo_reset():
    _ACC_TURBO_STATE.clear()


def acc_turbo_predict(df: pd.DataFrame, K: int = 4,
                      rate_factor: float = 2.0) -> np.ndarray:
    """
    ACC-Turbo (SIGCOMM 2022) — Appendix B, Algorithm 1.

    Fixed-K PERSISTENT online range-based clustering (Manhattan distance).
    Cluster ranges carry over across windows — faithful to ACC-Turbo's
    "always-on" design (§3.2).  Call acc_turbo_reset() between experiments.

    Features (flow-level approximation of packet-level features):
      max_pkt_len  ordinal  proxy for ip.len  (available in P4 per packet)
      proto        nominal  ip.proto          (available in P4 per packet)

    Note: ACC-Turbo does NOT use IAT — per-flow inter-arrival time requires
    stateful per-flow registers unavailable in existing P4 pipelines.
    This is xpkt_clubox's structural advantage over ACC-Turbo.

    Cluster assessment (§5.2): flag cluster if its flow fraction in this
    window exceeds rate_factor/K.  With K=4, rate_factor=2.0 flags any
    cluster that holds >50% of window flows (2× its fair share of 25%).
    """
    global _ACC_TURBO_STATE
    if df.empty:
        return np.array([], dtype=int)

    clusters = _ACC_TURBO_STATE          # shared persistent state
    n        = len(df)
    pkt_lens = df["feature1"].values.astype(float)
    protos   = df["proto"].values.astype(int)

    PL_RANGE = 1446.0   # fixed: Ethernet MTU 1500 - min IP+TCP 54

    assignments = np.full(n, 0, dtype=int)

    for i in range(n):
        pl = pkt_lens[i]
        pr = protos[i]

        # Seed phase: first K flows initialise K singleton clusters.
        if len(clusters) < K:
            clusters.append({'pl_min': pl, 'pl_max': pl, 'proto_set': {pr}})
            assignments[i] = len(clusters) - 1
            continue

        # ComputeDistance (Alg. 1, Appendix B): Manhattan distance.
        best_ci, best_d = 0, float('inf')
        for ci, c in enumerate(clusters):
            d = 0.0
            if pl < c['pl_min']:
                d += (c['pl_min'] - pl) / PL_RANGE
            elif pl > c['pl_max']:
                d += (pl - c['pl_max']) / PL_RANGE
            if pr not in c['proto_set']:
                d += 1.0
            if d < best_d:
                best_d, best_ci = d, ci

        # UpdateCluster: expand ranges on mismatch (ranges never shrink).
        if best_d > 0:
            c = clusters[best_ci]
            if pl < c['pl_min']:
                c['pl_min'] = pl
            elif pl > c['pl_max']:
                c['pl_max'] = pl
            c['proto_set'].add(pr)

        assignments[i] = best_ci

    # Cluster assessment (§5.2): rate-based maliciousness per window.
    threshold = min(rate_factor / K, 0.99)
    malicious = {ci for ci in range(len(clusters))
                 if np.sum(assignments == ci) / n > threshold}

    return np.array([1 if a in malicious else 0 for a in assignments],
                    dtype=int)


# ── xpkt_clubox prediction from CSVs ─────────────────────────────────────────

def clubox_predict_from_csv(df: pd.DataFrame,
                             cluster_boxes_path: str) -> np.ndarray:
    """
    Reconstruct xpkt_clubox per-flow predictions from cluster_boxes CSV.
    Bypasses the hardcoded C-code ATTACK_IP so any ground truth can be used.
    box_id == -1 or out-of-range → outlier_pred (majority-malicious rule).
    """
    if not os.path.exists(cluster_boxes_path):
        return np.full(len(df), -1, dtype=int)

    cb = pd.read_csv(cluster_boxes_path)
    box_labels = dict(zip(cb["box_id"].astype(int), cb["box_label"].astype(int)))
    box_count  = len(box_labels)

    if box_count > 0:
        mal_cnt      = sum(box_labels.values())
        outlier_pred = int(mal_cnt * 2 > box_count)
    else:
        outlier_pred = 0

    pred = []
    for bid in df["box_id"].astype(int):
        pred.append(box_labels.get(bid, outlier_pred))
    return np.array(pred, dtype=int)


# ── Confusion matrix helpers ──────────────────────────────────────────────────

def confusion(true_lbl: np.ndarray, pred_lbl: np.ndarray):
    tp = int(((pred_lbl == 1) & (true_lbl == 1)).sum())
    tn = int(((pred_lbl == 0) & (true_lbl == 0)).sum())
    fp = int(((pred_lbl == 1) & (true_lbl == 0)).sum())
    fn = int(((pred_lbl == 0) & (true_lbl == 1)).sum())
    return tp, tn, fp, fn


def prf(tp, tn, fp, fn):
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    return prec, rec, f1


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir")
    parser.add_argument("--mode", choices=["single", "distributed"],
                        default="single")
    parser.add_argument("--poseidon-k",    type=float, default=3.0)
    parser.add_argument("--jaqen-topk",    type=int,   default=3)
    parser.add_argument("--jaqen-fanout",  type=float, default=0.1)
    parser.add_argument("--acc-k",       type=int,   default=4,
                        help="ACC-Turbo number of clusters K (default 4)")
    parser.add_argument("--acc-factor",  type=float, default=2.0,
                        help="ACC-Turbo rate_factor: flag cluster if fraction "
                             "> rate_factor/K (default 2.0, i.e. 2× fair share)")
    parser.add_argument("--plot", action="store_true")
    parser.add_argument("--csv",  metavar="FILE",
                        help="save per-window results to CSV file")
    args = parser.parse_args()

    acc_turbo_reset()          # fresh cluster state for this experiment
    gt_fn = make_gt_fn(args.mode)

    files = sorted(
        glob.glob(os.path.join(args.output_dir, "sample_clusters_*.csv")),
        key=lambda p: int(
            os.path.basename(p)
            .replace("sample_clusters_", "").replace(".csv", "")
        ),
    )
    if not files:
        sys.exit(f"No sample_clusters_*.csv in {args.output_dir}")

    scenario = "Single-source (fixed IP)" if args.mode == "single" \
               else "Distributed DDoS (50k spoofed srcs, 200 victims in 200×/24)"
    print(f"Scenario : {scenario}")
    print(f"Windows  : {len(files)}")
    print(f"Poseidon k={args.poseidon_k}  Jaqen top_k={args.jaqen_topk}  "
          f"ACC-Turbo K={args.acc_k} factor={args.acc_factor}")
    print()

    hdr = (f"{'Win':>4}  {'xpkt_clubox':^23}  {'Poseidon':^23}  "
           f"{'Jaqen':^23}  {'ACC-Turbo':^23}")
    sub = (f"{'':>4}  " +
           (f"{'TP':>5} {'TN':>5} {'FP':>5} {'FN':>5}  " * 4))
    print(hdr)
    print(sub)
    print("-" * len(sub))

    agg = {n: dict(tp=0, tn=0, fp=0, fn=0)
           for n in ("clubox", "poseidon", "jaqen", "acc")}
    rows_f1 = []

    for f in files:
        wid = int(os.path.basename(f)
                  .replace("sample_clusters_", "").replace(".csv", ""))
        df = pd.read_csv(f)
        if df.empty:
            continue

        true_lbl = np.array(
            [gt_fn(r.src_ip, r.dst_ip) for r in df.itertuples(index=False)],
            dtype=int,
        )

        cb_path = os.path.join(args.output_dir, f"cluster_boxes_{wid}.csv")
        c_pred  = clubox_predict_from_csv(df, cb_path)
        c_tp, c_tn, c_fp, c_fn = confusion(true_lbl, c_pred)

        p_pred = poseidon_predict(df, k=args.poseidon_k)
        p_tp, p_tn, p_fp, p_fn = confusion(true_lbl, p_pred)

        j_pred = jaqen_predict(df, top_k=args.jaqen_topk,
                                fanout_thresh=args.jaqen_fanout)
        j_tp, j_tn, j_fp, j_fn = confusion(true_lbl, j_pred)

        a_pred = acc_turbo_predict(df, K=args.acc_k, rate_factor=args.acc_factor)
        a_tp, a_tn, a_fp, a_fn = confusion(true_lbl, a_pred)

        print(f"{wid:>4}  "
              f"{c_tp:>5} {c_tn:>5} {c_fp:>5} {c_fn:>5}  "
              f"{p_tp:>5} {p_tn:>5} {p_fp:>5} {p_fn:>5}  "
              f"{j_tp:>5} {j_tn:>5} {j_fp:>5} {j_fn:>5}  "
              f"{a_tp:>5} {a_tn:>5} {a_fp:>5} {a_fn:>5}")

        for name, (tp, tn, fp, fn) in [
            ("clubox",   (c_tp, c_tn, c_fp, c_fn)),
            ("poseidon", (p_tp, p_tn, p_fp, p_fn)),
            ("jaqen",    (j_tp, j_tn, j_fp, j_fn)),
            ("acc",      (a_tp, a_tn, a_fp, a_fn)),
        ]:
            agg[name]["tp"] += tp
            agg[name]["tn"] += tn
            agg[name]["fp"] += fp
            agg[name]["fn"] += fn

        c_p, c_r, c_f1 = prf(c_tp, c_tn, c_fp, c_fn)
        p_p, p_r, p_f1 = prf(p_tp, p_tn, p_fp, p_fn)
        j_p, j_r, j_f1 = prf(j_tp, j_tn, j_fp, j_fn)
        a_p, a_r, a_f1 = prf(a_tp, a_tn, a_fp, a_fn)
        rows_f1.append((wid, c_f1, p_f1, j_f1, a_f1,
                        c_tp, c_tn, c_fp, c_fn,
                        p_tp, p_tn, p_fp, p_fn,
                        j_tp, j_tn, j_fp, j_fn,
                        a_tp, a_tn, a_fp, a_fn,
                        c_p, c_r, p_p, p_r, j_p, j_r, a_p, a_r))

    # ── Aggregate summary ─────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print(f"{'System':<16}  {'TP':>7} {'TN':>7} {'FP':>7} {'FN':>7}  "
          f"{'Prec':>7} {'Recall':>7} {'F1':>7}")
    print("-" * 80)
    labels = {"clubox":   "xpkt_clubox",
              "poseidon": "Poseidon",
              "jaqen":    "Jaqen",
              "acc":      "ACC-Turbo"}
    for name in ("clubox", "poseidon", "jaqen", "acc"):
        a   = agg[name]
        p, r, f1 = prf(a["tp"], a["tn"], a["fp"], a["fn"])
        print(f"{labels[name]:<16}  "
              f"{a['tp']:>7} {a['tn']:>7} {a['fp']:>7} {a['fn']:>7}  "
              f"{p:>7.4f} {r:>7.4f} {f1:>7.4f}")
    print("=" * 80)

    # ── Optional CSV export ───────────────────────────────────────────────────
    if args.csv and rows_f1:
        import csv
        cols = [
            "window",
            "clubox_tp","clubox_tn","clubox_fp","clubox_fn",
            "clubox_prec","clubox_rec","clubox_f1",
            "poseidon_tp","poseidon_tn","poseidon_fp","poseidon_fn",
            "poseidon_prec","poseidon_rec","poseidon_f1",
            "jaqen_tp","jaqen_tn","jaqen_fp","jaqen_fn",
            "jaqen_prec","jaqen_rec","jaqen_f1",
            "acc_tp","acc_tn","acc_fp","acc_fn",
            "acc_prec","acc_rec","acc_f1",
        ]
        with open(args.csv, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(cols)
            for r in rows_f1:
                (wid, c_f1, p_f1, j_f1, a_f1,
                 c_tp, c_tn, c_fp, c_fn,
                 p_tp, p_tn, p_fp, p_fn,
                 j_tp, j_tn, j_fp, j_fn,
                 a_tp, a_tn, a_fp, a_fn,
                 c_p, c_r, p_p, p_r, j_p, j_r, a_p, a_r) = r
                w.writerow([
                    wid,
                    c_tp, c_tn, c_fp, c_fn,
                    f"{c_p:.4f}", f"{c_r:.4f}", f"{c_f1:.4f}",
                    p_tp, p_tn, p_fp, p_fn,
                    f"{p_p:.4f}", f"{p_r:.4f}", f"{p_f1:.4f}",
                    j_tp, j_tn, j_fp, j_fn,
                    f"{j_p:.4f}", f"{j_r:.4f}", f"{j_f1:.4f}",
                    a_tp, a_tn, a_fp, a_fn,
                    f"{a_p:.4f}", f"{a_r:.4f}", f"{a_f1:.4f}",
                ])
        print(f"\nCSV → {args.csv}")

    # ── Optional plot ─────────────────────────────────────────────────────────
    if args.plot and rows_f1:
        try:
            import matplotlib.pyplot as plt
            wins = [r[0] for r in rows_f1]
            fig, ax = plt.subplots(figsize=(13, 4))
            ax.plot(wins, [r[1] for r in rows_f1],
                    label="xpkt_clubox (CluBox+DT+LR)", marker="o", ms=4)
            ax.plot(wins, [r[2] for r in rows_f1],
                    label="Poseidon (src-IP HH)",        marker="s", ms=4)
            ax.plot(wins, [r[3] for r in rows_f1],
                    label="Jaqen (bidir HH)",            marker="^", ms=4)
            ax.plot(wins, [r[4] for r in rows_f1],
                    label="ACC-Turbo (dst-agg rate)",    marker="D", ms=4)
            ax.set_xlabel("Window ID (× 5000 flows)")
            ax.set_ylabel("F1 Score")
            sc = "Single-source" if args.mode == "single" else "Distributed DDoS"
            ax.set_title(f"Per-window F1 — {sc} scenario")
            ax.legend()
            ax.set_ylim(0, 1.05)
            ax.grid(True, alpha=0.3)
            out_path = os.path.join(
                args.output_dir, f"comparison_{args.mode}.png")
            fig.tight_layout()
            fig.savefig(out_path, dpi=150)
            print(f"\nPlot → {out_path}")
        except ImportError:
            print("\n[warn] matplotlib not available")


if __name__ == "__main__":
    main()
