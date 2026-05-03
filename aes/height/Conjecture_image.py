import random
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np

# ===============================
# 参数设置（可以调）
# ===============================
l = 22                  # 状态bit数（不要太大，否则跑不动）
N = 1 << l              # 节点总数
target_t = 18           # 想收集 2^t 个节点
target_size = 1 << target_t

MAX_LAMBDA = int((2 ** (l/2)) / l)

# ===============================
# 1. 生成随机函数 f
# ===============================
f = [random.randrange(N) for _ in range(N)]

# ===============================
# 2. 计算链 + height
# ===============================
def process_chain(start, Y_set, Y_height):
    visited = {}
    chain = []

    x = start
    step = 0

    while True:
        if x in visited:
            # case 1: cycle
            cycle_start = visited[x]
            end_type = "cycle"
            break

        if x in Y_set:
            # case 2: attach to existing Y
            cycle_start = len(chain)
            end_type = "attach"
            attach_node = x
            break

        visited[x] = step
        chain.append(x)
        x = f[x]
        step += 1

    height = {}
    length = len(chain)

    # ===========================
    # 计算 height
    # ===========================
    if end_type == "cycle":
        # cycle nodes height = 0
        for i in reversed(range(length)):
            if i >= cycle_start:
                height[chain[i]] = 0
            else:
                height[chain[i]] = height[chain[i+1]] + 1

    else:  # attach
        # 最后一个点接到已有节点
        height_last = Y_height[attach_node] + 1
        height[chain[-1]] = height_last

        for i in reversed(range(length - 1)):
            height[chain[i]] = height[chain[i+1]] + 1

    return chain, height

# ===============================
# 3. 构建 Y
# ===============================
Y_set = set()
Y_lambda = defaultdict(int)
Y_height = {}

print("开始收集节点...")
while len(Y_set) < target_size:
    start = random.randrange(N)
    if start in Y_set:
        continue

    chain, height = process_chain(start, Y_set, Y_height)

    for node in chain:
        if node not in Y_set:
            Y_set.add(node)
            Y_height[node] = height[node]
            lam = height[node]
            Y_lambda[lam] += 1

    # 每收集10%进度打印一次
    progress = len(Y_set) / target_size * 100
    if progress % 10 < 1:
        print(f"收集进度: {progress:.1f}% ({len(Y_set)}/{target_size})")

# ===============================
# 4. 统计结果
# ===============================
print("\n==== Height Distribution ====")
expected = 2 ** (target_t - l/2)
print(f"Expected scale ≈ {expected:.2f}\n")

# 整理绘图数据（过滤λ=0，只显示1到MAX_LAMBDA）
lambda_values = list(range(1, int(MAX_LAMBDA)+1))
y_lambda_values = [Y_lambda.get(lam, 0) for lam in lambda_values]

# 打印统计信息
for lam, count in zip(lambda_values, y_lambda_values):
    print(f"λ={lam:2d}  |Y_λ|={count:6d}  ratio={count/expected:.2f}")

# ===============================
# 5. 绘制柱状图
# ===============================
plt.rcParams['font.sans-serif'] = ['SimHei']  # 支持中文显示
plt.rcParams['axes.unicode_minus'] = False

# 创建画布
fig, ax = plt.subplots(figsize=(12, 6))

# 绘制柱状图
bars = ax.bar(lambda_values, y_lambda_values,
              color='#2E86AB', alpha=0.8, edgecolor='black', linewidth=0.5)

# 添加数值标签
for bar in bars:
    height = bar.get_height()
    if height > 0:  # 只显示非零值的标签
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}', ha='center', va='bottom', fontsize=8)

# 设置标题和轴标签
ax.set_title(f'Height分布柱状图 (l={l}, target_t={target_t})', fontsize=14, pad=20)
ax.set_xlabel('height)', fontsize=12)
ax.set_ylabel('|Y_λ| (节点数量)', fontsize=12)

# 设置横轴刻度
ax.set_xticks(lambda_values)
ax.set_xticklabels(lambda_values, fontsize=10)

# 添加网格线
ax.grid(axis='y', alpha=0.3, linestyle='--')

# 调整布局
plt.tight_layout()

# 显示图表
plt.show()

# 可选：保存图片
# plt.savefig('y_lambda_distribution.png', dpi=300, bbox_inches='tight')