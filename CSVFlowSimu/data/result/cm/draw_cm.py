import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# 1. 读取数据
fp = 'cm.csv'
df = pd.read_csv(fp)
df = df[df['Slice'] != 'TOTAL'].copy()
df['Slice'] = pd.to_numeric(df['Slice'])
df = df.sort_values('Slice')

# 计算总量
df['Actual_Benign'] = df['TP'] + df['FN']
df['Actual_Attack'] = df['TN'] + df['FP']

# 2. 绘图参数 (严格保留你的原始颜色定义)
plt.figure(figsize=(11, 6))

c_benign_tp = '#FFA500'     # 你的原始橘色
c_benign_total = '#FF8C00'  # 你的原始深橘
c_attack_fp =  '#0000FF'    # 你的原始蓝色
c_attack_total = '#00008B'  # 你的原始深蓝

# 3. 绘图逻辑分拆

# --- A. 良性流量 (不要 Slice 0 起点，防止出现垂直上升红叉线) ---
# 直接使用原始 df，它会从第一个真实数据点（Slice 1）开始画
plt.plot(df['Slice'], df['Actual_Benign'], label='Benign Total', 
         color=c_benign_total, marker='o', linestyle='--', linewidth=4, alpha=1.0)
plt.plot(df['Slice'], df['TP'], label='Benign Accepted', 
         color=c_benign_tp, marker='s', linewidth=4)

# --- B. 攻击流量 (手动补 0 起点，实现你期望的斜向爬坡效果) ---
# 只为蓝色线构造包含 0 的序列

plt.plot(df['Slice'], df['Actual_Attack'], label='Attack Total', 
         color=c_attack_total, marker='o', linestyle='--', linewidth=4, alpha=1.0)
plt.plot(df['Slice'], df['FP'], label='Attack Accepted', 
         color=c_attack_fp, marker='s', linewidth=4)

# attack_slice = np.insert(df['Slice'].values, 0, 0)
# attack_total = np.insert(df['Actual_Attack'].values, 0, 0)
# attack_serviced = np.insert(df['FP'].values, 0, 0)

# plt.plot(attack_slice, attack_total, label='TN+FP', 
#          color=c_attack_total, marker='o', linestyle='--', linewidth=3, alpha=1.0)
# plt.plot(attack_slice, attack_serviced, label='FP', 
#          color=c_attack_fp, marker='s', linewidth=3)

# 4. 坐标轴优化
# 调大 linthresh 是为了让 0 到第一个大数之间的连线“斜率”更缓、更明显
plt.yscale('symlog', linthresh=500) 

# 设置 y 轴底限为 0，留出顶部空间
max_val = max(df['Actual_Benign'].max(), df['Actual_Attack'].max())
plt.ylim(0, max_val * 5) 
plt.xlim(-0.2, df['Slice'].max() + 0.5)

plt.xlabel('Time Slice', fontweight='bold', fontsize=25)
plt.ylabel('Flow Count (Log Scale)', fontweight='bold', fontsize=25)

# 5. 美化
plt.xticks(np.arange(0, df['Slice'].max() + 1, 1))
plt.grid(True, which="both", ls="-", alpha=0.15)
plt.legend(loc='upper right', frameon=True, fontsize=25, shadow=True)

# 移除冗余边框
ax = plt.gca()

ax.tick_params(axis='both', which='major', labelsize=25, width=2, length=8)
ax.tick_params(axis='both', which='minor', labelsize=20, width=1.5, length=5)

ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

plt.tight_layout()
output_name = "simu_" + fp.replace('.csv', '_fig.pdf')
plt.savefig(output_name, format='pdf', dpi=600)
print(f"Saved to {output_name}")
# plt.show()