import pandas as pd
import numpy as np

# 1. 加载数据
file_path = 'sample_clusters_2_labeled.csv'
df = pd.read_csv(file_path)

def calculate_comprehensive_stats(df):
    # --- 功能 1: 统计各类别的全量样本总数 ---
    print("="*60)
    print(f"📊 各类别样本总数统计 (Total Label Counts)")
    print("="*60)
    label_counts = df['Label'].value_counts()
    for label, count in label_counts.items():
        print(f" - {label:<15}: {count:>6} 个样本")
    print("-" * 60)

    # --- 功能 2: 剔除离群点并计算纯度 ---
    df_valid = df[df['Cluster'] != -1].copy()
    outliers_count = len(df) - len(df_valid)
    
    if df_valid.empty:
        print("❌ 警告：剔除离群点后没有剩余样本！")
        return

    # 计算交叉表
    contingency_matrix = pd.crosstab(df_valid['Cluster'], df_valid['Label'])
    
    print(f"🔍 有效簇明细 (已剔除 {outliers_count} 个离群点):")
    print(f"{'簇编号':<8} | {'总样本':<8} | {'纯度':<8} | {'标签分布'}")
    print("-" * 60)

    cluster_purities = []
    for cluster_id in contingency_matrix.index:
        row = contingency_matrix.loc[cluster_id]
        total = row.sum()
        majority_count = row.max()
        purity = majority_count / total
        cluster_purities.append(purity)
        
        # 统计该簇中存在的标签及其数量
        dist_info = ", ".join([f"{l}: {c}" for l, c in row[row > 0].items()])
        print(f"{cluster_id:<8} | {total:<8} | {purity:>7.2%} | {dist_info}")

    # --- 功能 3: 汇总指标 ---
    macro_purity = np.mean(cluster_purities)
    weighted_purity = np.sum(contingency_matrix.max(axis=1)) / len(df_valid)

    print("-" * 60)
    print(f"🎯 平均簇纯度 (Macro Average): {macro_purity:.4%}")
    print(f"🎯 加权平均纯度 (Weighted Average): {weighted_purity:.4%}")
    print("="*60)

# 执行统计
calculate_comprehensive_stats(df)