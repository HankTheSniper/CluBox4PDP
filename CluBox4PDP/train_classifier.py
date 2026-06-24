#!/usr/bin/env python3
"""
Train box classifiers from cluster_boxes_*.csv output files.

Usage:
    python3 train_classifier.py [--threshold 0.3] [--max-depth 5]

Output:
    Prints decision tree structure and LR weights to stdout.
    Copy the DT if-else tree and LR weights into box_classifier.c,
    then set BOX_EVAL_THRESHOLD in box_classifier.h and rebuild.

CSV column format (produced by xpkt_clubox):
    box_id, min_f0, max_f0, min_f1_us, max_f1_us,
    box_points, box_volume,
    attack_count, benign_count, attack_ratio,
    box_score, box_label
"""

import argparse
import glob
import sys

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier, export_text


def load_data(pattern="cluster_boxes_*.csv"):
    files = sorted(glob.glob(pattern))
    if not files:
        sys.exit(f"No files matched '{pattern}'. Run xpkt_clubox first.")
    print(f"Loading {len(files)} CSV file(s): {files}")
    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f)
            df["_src"] = f
            dfs.append(df)
        except Exception as e:
            print(f"  Warning: could not read {f}: {e}")
    df = pd.concat(dfs, ignore_index=True)
    df = df[df["box_points"] > 0].copy()
    print(f"Total boxes loaded: {len(df)}")
    return df


SAMPLE_WINDOW = 5000

def compute_meta_features(df):
    """Prepare meta-features for training.

    box_ratio, box_volume come from CSV (written by main.c).
    box_ratio_sq is derived here. delta_points is box_points diff between windows.
    """
    # delta_points: difference between consecutive windows per source file
    deltas = []
    for src, group in df.groupby("_src"):
        pts = group["box_points"].values
        prev = np.concatenate([[0], pts[:-1]])
        deltas.append(pd.Series(pts - prev, index=group.index))
    df["delta_points"] = pd.concat(deltas)

    if "box_ratio" not in df.columns:
        df["box_ratio"] = df["box_points"] / SAMPLE_WINDOW

    df["box_ratio_sq"] = df["box_ratio"] ** 2

    return df


def evaluate_thresholds(df, thresholds, max_depth):
    print("\n=== Cross-validation results ===")
    print(f"{'Threshold':>10}  {'Pos':>5}  {'Neg':>5}  {'DT CV':>8}  {'LR CV':>8}")
    results = {}
    for thresh in thresholds:
        y = (df["attack_ratio"] >= thresh).astype(int)
        n_pos, n_neg = y.sum(), (1 - y).sum()
        if n_pos < 3 or n_neg < 3:
            print(f"{thresh:>10.2f}  {n_pos:>5}  {n_neg:>5}   (skip: too few samples)")
            continue

        X_s = df[["min_f0", "max_f0", "min_f1_us", "max_f1_us"]].values
        X_m_raw = df[["box_ratio", "box_ratio_sq", "box_volume", "delta_points"]].values
        sc = StandardScaler().fit(X_m_raw)
        X_m = sc.transform(X_m_raw)

        cv = StratifiedKFold(n_splits=min(5, n_pos), shuffle=True, random_state=42)
        dt = DecisionTreeClassifier(max_depth=max_depth, random_state=42)
        lr = LogisticRegression(max_iter=1000, random_state=42)

        dt_score = cross_val_score(dt, X_s, y, cv=cv, scoring="f1").mean()
        lr_score = cross_val_score(lr, X_m, y, cv=cv, scoring="f1").mean()

        print(f"{thresh:>10.2f}  {n_pos:>5}  {n_neg:>5}  {dt_score:>8.3f}  {lr_score:>8.3f}")
        results[thresh] = (dt_score, lr_score, sc)
    return results


def export_model(df, threshold, max_depth):
    y = (df["attack_ratio"] >= threshold).astype(int)
    X_s = df[["min_f0", "max_f0", "min_f1_us", "max_f1_us"]].values
    X_m_raw = df[["box_ratio", "box_ratio_sq", "box_volume", "delta_points"]].values
    sc = StandardScaler().fit(X_m_raw)
    X_m = sc.transform(X_m_raw)

    dt = DecisionTreeClassifier(max_depth=max_depth, random_state=42).fit(X_s, y)
    lr = LogisticRegression(max_iter=1000, random_state=42).fit(X_m, y)

    print("\n=== Decision Tree (copy into classify_box_spatial) ===")
    print(export_text(dt, feature_names=["min_f0", "max_f0", "min_f1_us", "max_f1_us"]))

    print("=== Logistic Regression weights (copy into score_box_meta) ===")
    print(f"LR_MEAN  = {{{', '.join(f'{v:.6f}f' for v in sc.mean_)}}}")
    print(f"LR_SCALE = {{{', '.join(f'{v:.6f}f' for v in sc.scale_)}}}")
    print(f"LR_W     = {{{', '.join(f'{v:.6f}f' for v in lr.coef_[0])}}}")
    print(f"LR_BIAS  = {lr.intercept_[0]:.6f}f")

    print("\n=== C template for box_classifier.c ===")
    print("""
#include <math.h>
#include "box_classifier.h"

static const float LR_MEAN[4]  = {LR_MEAN};
static const float LR_SCALE[4] = {LR_SCALE};
static const float LR_W[4]     = {LR_W};
static const float LR_BIAS     =  LR_BIAS;

float score_box_meta(float box_ratio, float box_volume, int delta_points)
{
    float x[4] = { box_ratio, box_ratio * box_ratio, box_volume, (float)delta_points };
    float z = LR_BIAS;
    for (int i = 0; i < 4; i++)
        z += LR_W[i] * (x[i] - LR_MEAN[i]) / LR_SCALE[i];
    return 1.0f / (1.0f + expf(-z));
}
""".replace("{LR_MEAN}", ", ".join(f"{v:.6f}f" for v in sc.mean_))
   .replace("{LR_SCALE}", ", ".join(f"{v:.6f}f" for v in sc.scale_))
   .replace("{LR_W}", ", ".join(f"{v:.6f}f" for v in lr.coef_[0]))
   .replace("LR_BIAS", f"{lr.intercept_[0]:.6f}f"))


def main():
    parser = argparse.ArgumentParser(description="Train box classifiers for xpkt_clubox")
    parser.add_argument("--threshold", type=float, default=None,
                        help="Attack ratio threshold for final export (skip CV if set)")
    parser.add_argument("--max-depth", type=int, default=5,
                        help="Decision tree max depth (default: 5)")
    parser.add_argument("--pattern", default="cluster_boxes_*.csv",
                        help="Glob pattern for input CSV files")
    args = parser.parse_args()

    df = load_data(args.pattern)
    df = compute_meta_features(df)

    thresholds = [0.1, 0.2, 0.3, 0.5, 0.7]
    results = evaluate_thresholds(df, thresholds, args.max_depth)

    if args.threshold is not None:
        best = args.threshold
    elif results:
        # pick threshold with highest combined DT+LR F1
        best = max(results, key=lambda t: results[t][0] + results[t][1])
        print(f"\nAuto-selected threshold: {best} (highest sum of DT+LR F1)")
    else:
        sys.exit("No valid threshold found. Collect more training data.")

    export_model(df, best, args.max_depth)


if __name__ == "__main__":
    main()
