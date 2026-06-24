#!/usr/bin/env python3
"""
plot_linerate_main.py — Combined 1×2 figure:
  Left : single benign run (stable throughput)
  Right: three-scenario overlay (benign / single-source / distributed DDoS)

Usage:
    python3 plot_linerate_main.py [--out linerate_combined.png]
"""

import argparse
import os
import sys

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.lines as mlines

SAMPLE_WINDOW = 5000
PKT_COUNT     = 3

BENIGN_DIR   = "output_20260608_000751"
SINGLE_DIR   = "output_20260420_092354"
DIST_DIR     = "output_20260420_082159"

REF_LINES = [
    (1.04, "10 GbE line rate (1200 B avg pkt)", "#E53935", "--"),
    (1.79, "10 GbE line rate (700 B avg pkt)",  "#FB8C00", "-."),
]

SCENARIOS = [
    (BENIGN_DIR,  "Benign",               "#1565C0", "o"),
    (SINGLE_DIR,  "Single-source DDoS",   "#C62828", "s"),
    (DIST_DIR,    "Distributed DDoS",     "#2E7D32", "^"),
]

FS_LABEL  = 16   # axis label fontsize
FS_TICK   = 15   # tick label fontsize
FS_LEGEND = 14   # legend fontsize
LW        = 2.0
MS        = 5


def load(out_dir):
    path = os.path.join(out_dir, "timing.csv")
    if not os.path.exists(path):
        sys.exit(f"timing.csv not found in {out_dir}/")
    df = pd.read_csv(path)
    wins    = df["window_id"].values
    total_us = df["total_us"].values.astype(float)
    mpps    = SAMPLE_WINDOW * PKT_COUNT / (total_us * 1e-6) / 1e6
    recluster = df["is_recluster"].values.astype(bool)
    return wins, mpps, recluster


def draw_refs(ax):
    for rate, label, color, ls in REF_LINES:
        ax.axhline(rate, color=color, linestyle=ls, linewidth=1.8,
                   alpha=0.85, zorder=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="linerate_combined.png")
    args = parser.parse_args()

    fig, axes = plt.subplots(1, 2, figsize=(18, 5), sharey=False)
    fig.subplots_adjust(wspace=0.28)

    # ── Left subplot: benign only ─────────────────────────────────────────────
    ax = axes[0]
    wins, mpps, recluster = load(BENIGN_DIR)
    color, marker = SCENARIOS[0][2], SCENARIOS[0][3]

    ax.plot(wins, mpps, color=color, linewidth=LW, marker=marker,
            markersize=MS, zorder=3)
    draw_refs(ax)

    stable_mean = mpps[~recluster].mean()
    ax.axhline(stable_mean, color=color, linestyle=":", linewidth=1.2, alpha=0.5)

    ax.set_xlabel("Time Window (× 5 000 flows)", fontsize=FS_LABEL)
    ax.set_ylabel("Throughput (Mpps)", fontsize=FS_LABEL)
    ax.set_xlim(wins[0] - 0.5, wins[-1] + 2.0)
    ax.set_ylim(bottom=0, top=mpps.max() * 1.18)
    ax.grid(True, alpha=0.3, linestyle=":")
    ax.tick_params(axis="both", labelsize=FS_TICK)

    # ── Right subplot: three scenarios ────────────────────────────────────────
    ax = axes[1]
    all_mpps = []
    for out_dir, label, color, marker in SCENARIOS:
        wins, mpps, _ = load(out_dir)
        all_mpps.extend(mpps.tolist())
        ax.plot(wins, mpps, color=color, linewidth=LW, marker=marker,
                markersize=MS, zorder=3)
    draw_refs(ax)

    ax.set_xlabel("Time Window (× 5 000 flows)", fontsize=FS_LABEL)
    ax.set_ylabel("Throughput (Mpps)", fontsize=FS_LABEL)
    ax.set_xlim(-0.5, 30.5)
    ax.set_ylim(bottom=0, top=max(all_mpps) * 1.15)
    ax.grid(True, alpha=0.3, linestyle=":")
    ax.tick_params(axis="both", labelsize=FS_TICK)

    # ── Shared horizontal legend above both subplots ──────────────────────────
    legend_handles = []
    for _, label, color, marker in SCENARIOS:
        legend_handles.append(
            mlines.Line2D([], [], color=color, marker=marker,
                          linewidth=LW, markersize=MS + 1, label=label))
    for rate, label, color, ls in REF_LINES:
        legend_handles.append(
            mlines.Line2D([], [], color=color, linestyle=ls,
                          linewidth=1.8, label=label))

    fig.legend(handles=legend_handles,
               loc="upper center",
               ncol=len(legend_handles),
               fontsize=FS_LEGEND,
               bbox_to_anchor=(0.5, 1.04),
               frameon=True, edgecolor="gray")

    fig.savefig(args.out, dpi=150, bbox_inches="tight")
    print(f"Saved → {args.out}")


if __name__ == "__main__":
    main()
