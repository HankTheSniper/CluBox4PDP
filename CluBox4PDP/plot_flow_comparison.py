#!/usr/bin/env python3
"""
plot_flow_comparison.py
Draws a 1×4 row of subplots — one per detection system — showing per-window
flow counts for Benign Total, Benign Accepted, Attack Total, Attack Accepted.

Usage:
    python3 plot_flow_comparison.py results_distributed.csv [--out comparison_flows.png]
    python3 plot_flow_comparison.py results_single.csv      --out comparison_flows_single.png
"""

import argparse
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.lines as mlines

SYSTEMS = [
    ("opt4PDP(CluBox)", "clubox"),
    ("Poseidon",        "poseidon"),
    ("Jaqen",           "jaqen"),
    ("ACC-Turbo",       "acc"),
]

C_BENIGN  = "#2196F3"
C_ATTACK  = "#F44336"
LS_TOTAL  = "--"
LS_ACCEPT = "-"
LW = 1.8
MS = 4


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", help="Per-window results CSV")
    parser.add_argument("--out", default="comparison_flows.png")
    parser.add_argument("--title", default="")
    args = parser.parse_args()

    df = pd.read_csv(args.csv)
    wins = df["window"].values

    fig, axes = plt.subplots(1, 4, figsize=(22, 5), sharey=False)
    fig.subplots_adjust(wspace=0.28)

    for ax, (sys_name, prefix) in zip(axes, SYSTEMS):
        tp = df[f"{prefix}_tp"].values
        tn = df[f"{prefix}_tn"].values
        fp = df[f"{prefix}_fp"].values
        fn = df[f"{prefix}_fn"].values

        benign_total    = tn + fp
        benign_accepted = tn
        attack_total    = tp + fn
        attack_accepted = fn

        ax.plot(wins, benign_total,    color=C_BENIGN, linestyle=LS_TOTAL,
                linewidth=LW, marker="o", markersize=MS)
        ax.plot(wins, benign_accepted, color=C_BENIGN, linestyle=LS_ACCEPT,
                linewidth=LW, marker="o", markersize=MS, clip_on=False)
        ax.plot(wins, attack_total,    color=C_ATTACK, linestyle=LS_TOTAL,
                linewidth=LW, marker="s", markersize=MS)
        ax.plot(wins, attack_accepted, color=C_ATTACK, linestyle=LS_ACCEPT,
                linewidth=LW, marker="s", markersize=MS, clip_on=False)

        ax.set_title(sys_name, fontsize=13, fontweight="bold")
        ax.set_xlabel("Time Window", fontsize=11)
        ax.set_xlim(wins[0] - 0.5, wins[-1] + 0.5)
        ax.set_ylim(bottom=0)
        ax.grid(True, alpha=0.3, linestyle=":")
        ax.tick_params(axis="both", labelsize=9)

    axes[0].set_ylabel("Flow Count", fontsize=11)

    legend_handles = [
        mlines.Line2D([], [], color=C_BENIGN, linestyle=LS_TOTAL,
                      linewidth=LW, marker="o", markersize=MS, label="Benign Total"),
        mlines.Line2D([], [], color=C_BENIGN, linestyle=LS_ACCEPT,
                      linewidth=LW, marker="o", markersize=MS, label="Benign Accepted"),
        mlines.Line2D([], [], color=C_ATTACK, linestyle=LS_TOTAL,
                      linewidth=LW, marker="s", markersize=MS, label="Attack Total"),
        mlines.Line2D([], [], color=C_ATTACK, linestyle=LS_ACCEPT,
                      linewidth=LW, marker="s", markersize=MS, label="Attack Accepted"),
    ]
    fig.legend(handles=legend_handles, loc="upper center",
               ncol=4, fontsize=11,
               bbox_to_anchor=(0.5, 1.04),
               frameon=True, edgecolor="gray")

    if args.title:
        fig.suptitle(args.title, fontsize=14, y=1.10)

    fig.savefig(args.out, dpi=150, bbox_inches="tight")
    print(f"Saved → {args.out}")


if __name__ == "__main__":
    main()
