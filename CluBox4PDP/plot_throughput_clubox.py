#!/usr/bin/env python3
"""
plot_throughput_clubox.py — Plot opt4PDP(CluBox) throughput from output directory.

Reads:
  <output_dir>/results.csv  — window_id, mpps, gbps, cm_*
  <output_dir>/timing.csv   — window_id, total_us (per-window processing latency)

Output: throughput_clubox.png (dual-Y-axis figure)
  Left Y  : Throughput (Mpps)
  Right Y : Processing latency per window (µs)

Usage:
  python3 plot_throughput_clubox.py <output_dir> [--out throughput_clubox.png]
  python3 plot_throughput_clubox.py               # auto-selects latest output_*/
"""

import argparse
import glob
import os
import sys

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker


def latest_output_dir():
    dirs = sorted(glob.glob("output_*/"))
    if not dirs:
        sys.exit("No output_*/ directories found. Run xpkt_clubox first.")
    return dirs[-1].rstrip("/")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", nargs="?", default=None,
                        help="Output directory from xpkt_clubox run "
                             "(default: latest output_*/)")
    parser.add_argument("--out", default="throughput_clubox.png",
                        help="Output PNG path (default: throughput_clubox.png)")
    parser.add_argument("--title", default="opt4PDP(CluBox) — Throughput & Processing Latency")
    args = parser.parse_args()

    out_dir = args.output_dir or latest_output_dir()
    print(f"Reading from: {out_dir}/")

    results_path = os.path.join(out_dir, "results.csv")
    timing_path  = os.path.join(out_dir, "timing.csv")

    if not os.path.exists(results_path):
        sys.exit(f"results.csv not found in {out_dir}/")

    df_res = pd.read_csv(results_path)
    wins   = df_res["window_id"].values
    mpps   = df_res["mpps"].values
    gbps   = df_res["gbps"].values

    has_timing = os.path.exists(timing_path)
    if has_timing:
        df_tim    = pd.read_csv(timing_path)
        total_us  = df_tim["total_us"].values
    else:
        print("[warn] timing.csv not found — skipping latency axis")

    # ── Figure ────────────────────────────────────────────────────────────────
    fig, ax1 = plt.subplots(figsize=(10, 4.5))

    COLOR_MPPS = "#1565C0"   # dark blue
    COLOR_LAT  = "#E65100"   # dark orange

    ln1 = ax1.plot(wins, mpps, color=COLOR_MPPS, linewidth=2,
                   marker="o", markersize=5, label="Throughput (Mpps)")
    ax1.set_xlabel("Time Window (× 5 000 flows)", fontsize=12)
    ax1.set_ylabel("Throughput (Mpps)", fontsize=12, color=COLOR_MPPS)
    ax1.tick_params(axis="y", labelcolor=COLOR_MPPS)
    ax1.set_xlim(wins[0] - 0.5, wins[-1] + 0.5)
    ax1.set_ylim(bottom=0)
    ax1.grid(True, alpha=0.3, linestyle=":")
    ax1.yaxis.set_major_formatter(ticker.FormatStrFormatter("%.3f"))

    lines = ln1
    labels = [l.get_label() for l in lines]

    if has_timing:
        ax2 = ax1.twinx()
        ln2 = ax2.plot(wins, total_us, color=COLOR_LAT, linewidth=1.8,
                       linestyle="--", marker="s", markersize=4,
                       label="Processing latency (µs/window)")
        ax2.set_ylabel("Processing Latency (µs / window)", fontsize=12,
                       color=COLOR_LAT)
        ax2.tick_params(axis="y", labelcolor=COLOR_LAT)
        ax2.set_ylim(bottom=0)
        lines  = ln1 + ln2
        labels = [l.get_label() for l in lines]

    ax1.legend(lines, labels, loc="upper left", fontsize=10, framealpha=0.9)
    ax1.set_title(args.title, fontsize=13, fontweight="bold", pad=10)

    # ── Summary stats ─────────────────────────────────────────────────────────
    mean_mpps = mpps.mean()
    peak_mpps = mpps.max()
    mean_gbps = gbps.mean()
    note = (f"Mean {mean_mpps:.3f} Mpps  |  Peak {peak_mpps:.3f} Mpps  |  "
            f"Mean {mean_gbps:.3f} Gbps")
    fig.text(0.5, -0.02, note, ha="center", fontsize=10, color="gray")

    fig.tight_layout()
    fig.savefig(args.out, dpi=150, bbox_inches="tight")
    print(f"Saved → {args.out}")
    print()
    print(f"  Mean throughput : {mean_mpps:.4f} Mpps  ({mean_gbps:.4f} Gbps)")
    print(f"  Peak throughput : {peak_mpps:.4f} Mpps")
    if has_timing:
        print(f"  Mean latency    : {total_us.mean():.1f} µs/window")
        print(f"  Max  latency    : {total_us.max():.1f} µs/window")


if __name__ == "__main__":
    main()
