import hashlib
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import numpy as np

# 设置中文字体（如果需要显示中文）
plt.rcParams['font.sans-serif'] = ['SimHei']  # 黑体
plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题


# ================= PRF =================
def prf(input_bits: str, s: int, n: int) -> str:  # 新增参数n：循环左移位数
    if len(input_bits) != s:
        raise ValueError(f"输入必须是 {s} 位")

    data = input_bits.encode('utf-8')
    h = hashlib.md5(data).hexdigest()
    bits = bin(int(h, 16))[2:].zfill(128)

    rotated = bits[n:] + bits[:n]
    return rotated[:s]


# ================= 主算法 =================
def analyze(s, n_shift):  # 新增参数n_shift：传入当前PRF的循环移位数
    N = 1 << s

    visited = {}  # 0/无: 未访问, 1: 当前路径中, 2: 已完成
    component_id = {}
    height = {}
    root = {}

    comp_sizes = defaultdict(int)
    comp_index = 0

    for i in range(N):
        start = format(i, f'0{s}b')
        if start in visited:
            continue

        path = []
        path_set = set()

        cur = start

        # ========= 构造路径 =========
        while cur not in visited:
            visited[cur] = 1
            path.append(cur)
            path_set.add(cur)
            cur = prf(cur, s, n_shift)  # 传入循环移位数

        # ========= 情况1：发现新环 =========
        if cur in path_set:
            cycle = []

            # 找到环
            while True:
                node = path.pop()
                path_set.remove(node)
                cycle.append(node)
                if node == cur:
                    break

            # 标记环
            for node in cycle:
                height[node] = 0
                root[node] = node
                component_id[node] = comp_index
                visited[node] = 2

            # 处理树
            while path:
                node = path.pop()
                path_set.remove(node)
                nxt = prf(node, s, n_shift)
                height[node] = height[nxt] + 1
                root[node] = root[nxt]
                component_id[node] = comp_index
                visited[node] = 2

        # ========= 情况2：接入已有结构 =========
        else:
            # cur 已经在之前处理过
            while path:
                node = path.pop()
                path_set.remove(node)
                nxt = prf(node, s, n_shift)
                height[node] = height[nxt] + 1
                root[node] = root[nxt]
                component_id[node] = component_id[nxt]
                visited[node] = 2

        comp_index += 1

    # ========= 统计连通分量大小 =========
    for node, cid in component_id.items():
        comp_sizes[cid] += 1

    # ========= 最大连通分量 =========
    max_comp = max(comp_sizes, key=lambda x: comp_sizes[x])

    # ========= 每个树（按 root）大小 =========
    tree_sizes = defaultdict(int)

    for node in component_id:
        if component_id[node] == max_comp:
            tree_sizes[root[node]] += 1

    # ========= 最大树 =========
    max_root = max(tree_sizes, key=lambda x: tree_sizes[x])

    # ========= 最大树的 height 分布 =========
    height_dist = Counter()
    for node in component_id:
        if component_id[node] == max_comp and root[node] == max_root:
            h = height[node]
            height_dist[h] += 1

    return {
        "height_distribution": height_dist,
        "max_component_size": comp_sizes[max_comp],
        "largest_tree_size": tree_sizes[max_root]
    }


# ========= 绘制平均高度分布柱状图函数 =========
def plot_avg_height_distribution(avg_height_dist):
    """
    绘制8次实验后的高度平均分布柱状图
    :param avg_height_dist: 高度值对应的平均个数
    """
    # 准备数据
    heights = sorted(avg_height_dist.keys())
    avg_counts = [avg_height_dist[h] for h in heights]

    # 创建画布
    fig, ax = plt.subplots(figsize=(12, 6))

    # 绘制柱状图
    bars = ax.bar(heights, avg_counts, color='#2E86AB', alpha=0.8, edgecolor='black', linewidth=0.5)

    # 设置标签和标题
    ax.set_xlabel('Height值', fontsize=12, fontweight='bold')
    ax.set_ylabel('8次实验平均节点数量', fontsize=12, fontweight='bold')
    ax.set_title('8个不同方程最大树Height平均分布柱状图', fontsize=14, fontweight='bold', pad=20)

    # 添加数值标签（保留1位小数）
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2., height + 0.5,
                f'{height:.1f}', ha='center', va='bottom', fontsize=9)

    # 设置网格
    ax.grid(axis='y', alpha=0.3, linestyle='-')

    # 调整布局
    plt.tight_layout()

    # 显示图表
    plt.show()


# ================= 批量运行8次实验 =================
if __name__ == "__main__":
    s = 25  # 建议 10~16，可根据需要调整
    shift_values = range(8)  # 循环移位数0-7
    all_height_dists = []  # 存储8次实验的height分布

    # 执行8次实验
    for n in shift_values:
        print(f"正在运行实验：循环移位数 n={n}，s={s}...")
        result = analyze(s, n)
        all_height_dists.append(result["height_distribution"])
        print(
            f"实验 n={n} 完成，最大连通分量大小: {result['max_component_size']}, 最大树大小: {result['largest_tree_size']}")

    # 计算每个height值的平均个数
    avg_height_dist = defaultdict(float)
    all_heights = set()
    # 收集所有实验中出现的height值
    for dist in all_height_dists:
        all_heights.update(dist.keys())

    # 对每个height值计算8次实验的平均值
    for h in sorted(all_heights):
        total_count = 0
        for dist in all_height_dists:
            total_count += dist.get(h, 0)  # 无该height值则计0
        avg_height_dist[h] = total_count / len(shift_values)

    # 打印平均分布结果
    print("\n" + "=" * 50)
    print("8次实验 Height 平均分布结果：")
    print("=" * 50)
    for h in sorted(avg_height_dist):
        print(f"h={h}: 平均个数 = {avg_height_dist[h]:.2f}")

    # 绘制平均分布柱状图
    print("\n绘制8次实验的高度平均分布柱状图...")
    plot_avg_height_distribution(avg_height_dist)