#!/usr/bin/env python3
"""
calc_drop_reject.py — 从 output 目录直接计算 xpkt_clubox 的
  拒绝率 (Attack Rejection Rate) = TP / (TP + FN)  攻击流被正确拦截的比例
  丢包率 (Benign Drop Rate)       = FP / (TN + FP)  良性流被误拦截的比例

Usage:
  python3 calc_drop_reject.py <output_dir> [--mode single|distributed] [--csv out.csv]
"""

import argparse
import glob
import os
import sys

import numpy as np
import pandas as pd


# ── Ground truth (与 compare_baselines.py 保持一致) ────────────────────────

def make_gt_fn(mode: str):
    if mode == "single":
        ATTACK_IP = "192.168.50.1"
        return lambda src, dst: int(src == ATTACK_IP or dst == ATTACK_IP)
    else:
        return lambda src, dst: int(src.startswith("198.") or dst.startswith("198."))


# ── 从 cluster_boxes CSV 重建 per-flow 预测 ─────────────────────────────────

def clubox_predict(df: pd.DataFrame, cluster_boxes_path: str) -> np.ndarray:
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

    return np.array(
        [box_labels.get(int(bid), outlier_pred) for bid in df["box_id"]],
        dtype=int,
    )


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir")
    parser.add_argument("--mode", choices=["single", "distributed"], default="single")
    parser.add_argument("--csv", metavar="FILE", help="保存逐窗口结果到 CSV")
    args = parser.parse_args()

    gt_fn = make_gt_fn(args.mode)

    files = sorted(
        glob.glob(os.path.join(args.output_dir, "sample_clusters_*.csv")),
        key=lambda p: int(
            os.path.basename(p).replace("sample_clusters_", "").replace(".csv", "")
        ),
    )
    if not files:
        sys.exit(f"No sample_clusters_*.csv in {args.output_dir}")

    scenario = "Single-source" if args.mode == "single" else "Distributed DDoS"
    print(f"Scenario : {scenario}")
    print(f"Windows  : {len(files)}")
    print()

    header = (f"{'Win':>4}  {'Attack_Total':>12} {'Attack_Reject':>13} "
              f"{'Reject_Rate':>11}  {'Benign_Total':>12} {'Benign_Drop':>11} "
              f"{'Drop_Rate':>9}")
    print(header)
    print("-" * len(header))

    agg = dict(tp=0, tn=0, fp=0, fn=0)
    rows = []

    for f in files:
        wid = int(os.path.basename(f).replace("sample_clusters_", "").replace(".csv", ""))
        df  = pd.read_csv(f)
        if df.empty:
            continue

        true_lbl = np.array(
            [gt_fn(r.src_ip, r.dst_ip) for r in df.itertuples(index=False)],
            dtype=int,
        )

        cb_path = os.path.join(args.output_dir, f"cluster_boxes_{wid}.csv")
        pred    = clubox_predict(df, cb_path)

        tp = int(((pred == 1) & (true_lbl == 1)).sum())
        tn = int(((pred == 0) & (true_lbl == 0)).sum())
        fp = int(((pred == 1) & (true_lbl == 0)).sum())
        fn = int(((pred == 0) & (true_lbl == 1)).sum())

        attack_total  = tp + fn
        benign_total  = tn + fp
        reject_rate   = tp / attack_total if attack_total > 0 else float("nan")
        drop_rate     = fp / benign_total if benign_total > 0 else float("nan")

        print(f"{wid:>4}  {attack_total:>12} {tp:>13} "
              f"{reject_rate:>11.4f}  {benign_total:>12} {fp:>11} "
              f"{drop_rate:>9.4f}")

        for k, v in [("tp", tp), ("tn", tn), ("fp", fp), ("fn", fn)]:
            agg[k] += v

        rows.append((wid, attack_total, tp, fn, reject_rate,
                     benign_total, tn, fp, drop_rate))

    # ── Aggregate ─────────────────────────────────────────────────────────
    atp = agg["tp"] + agg["fn"]
    btp = agg["tn"] + agg["fp"]
    agg_reject = agg["tp"] / atp if atp > 0 else float("nan")
    agg_drop   = agg["fp"] / btp if btp > 0 else float("nan")

    print("-" * len(header))
    print(f"{'AGG':>4}  {atp:>12} {agg['tp']:>13} "
          f"{agg_reject:>11.4f}  {btp:>12} {agg['fp']:>11} "
          f"{agg_drop:>9.4f}")
    print()
    print(f"Attack Rejection Rate (Recall) : {agg_reject:.4f}  "
          f"({agg['tp']}/{atp} attack flows blocked)")
    print(f"Benign Drop Rate (FPR)         : {agg_drop:.4f}  "
          f"({agg['fp']}/{btp} benign flows wrongly blocked)")

    # ── Optional CSV ──────────────────────────────────────────────────────
    if args.csv and rows:
        import csv
        cols = ["window",
                "attack_total", "attack_rejected", "attack_passthrough", "rejection_rate",
                "benign_total",  "benign_accepted",  "benign_dropped",    "drop_rate"]
        with open(args.csv, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(cols)
            for (wid, at, tp, fn, rr, bt, tn, fp, dr) in rows:
                w.writerow([wid, at, tp, fn, f"{rr:.4f}",
                            bt, tn, fp, f"{dr:.4f}"])
        print(f"\nCSV → {args.csv}")


if __name__ == "__main__":
    main()
