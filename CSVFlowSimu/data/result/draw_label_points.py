import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ================= 学术绘图配置 =================
plt.rcParams["font.family"] = "Times New Roman"
plt.rcParams["axes.unicode_minus"] = False
sns.set_context("paper", font_scale=1.5)
sns.set_style("ticks")

# 1. 文件与维度设置
points_file = '2026-01-26-03-27-17_dbscan_20.00_8_0_aaaai_0_points.csv'
SAVE_PDF = True  # 建议保存为PDF以获得最高清晰度

# 2. 加载数据
df_points = pd.read_csv(points_file)
feature_names = df_points.columns[:-2].tolist()
label_col = df_points.columns[-2]  # 倒数第二列是真实标签

# 选择绘图维度 (例如 1: IAT Max, 0: Pkt Len Max)
DIM_X, DIM_Y = 1, 0 
x_name, y_name = feature_names[DIM_X], feature_names[DIM_Y]

# 3. 绘图初始化
fig, ax = plt.subplots(figsize=(8, 6))

# 4. 颜色与样式配置
# 使用 'Set1' 或 'Dark2' 等区分度明显的调色板
unique_labels = df_points[label_col].unique()
palette = sns.color_palette("bright", len(unique_labels))

# 5. 绘制散点图 (按 Label 着色)
# 我们这里不再区分 Style，只用颜色代表标签，这样视觉更纯粹
scatter = sns.scatterplot(
    data=df_points, 
    x=x_name, 
    y=y_name, 
    hue=label_col,    # 核心：按真实标签着色
    palette=palette,
    s=40, 
    alpha=0.6, 
    edgecolor=None,   # 去掉边缘色让高密度区更自然
    ax=ax
)

# 6. 细节修饰
ax.set_xlabel(f"{x_name}", fontsize=25, fontweight='bold')
ax.set_ylabel(f"{y_name}", fontsize=25, fontweight='bold')
# ax.set_title("Mapped First 3 Packets Flow Data", fontsize=16, pad=15)

# 移除冗余边框
sns.despine()

# 图例优化：放在图外，防止遮挡关键簇
plt.legend(
    loc='upper right',            # 自动寻找不遮挡数据点的空白处
    frameon=True,          # 开启边框
    shadow=False, 
    edgecolor='black',     # 给图例加个细黑边，显得更严谨
    fontsize=25,
)

plt.tight_layout()

# 7. 保存与展示
if SAVE_PDF:
    output_name = points_file.replace(".csv", "_ground_truth.pdf")
    plt.savefig(output_name, format='pdf', dpi=600)
    print(f"Saved to {output_name}")
else:
    plt.show()