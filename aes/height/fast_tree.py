import hashlib
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import numpy as np

# 设置中文字体（如果需要显示中文）
plt.rcParams['font.sans-serif'] = ['SimHei']  # 黑体
plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题


# ================= PRF =================
def prf(input_bits: str, s: int) -> str:
    if len(input_bits) != s:
        raise ValueError(f"输入必须是 {s} 位")

    import hashlib
    data = input_bits.encode('utf-8')
    h = hashlib.md5(data).hexdigest()
    bits = bin(int(h, 16))[2:].zfill(128)

    # ========== 在这里修改循环左移位数 n ==========
    n = 0
    # ===========================================

    rotated = bits[n:] + bits[:n]
    return rotated[:s]


# ================= 主算法 =================
def analyze(s):
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
            cur = prf(cur, s)

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
                nxt = prf(node, s)
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
                nxt = prf(node, s)
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
    max_height = 0
    total_height = 0  # 用于计算平均值
    node_count = 0  # 节点总数

    for node in component_id:
        if component_id[node] == max_comp and root[node] == max_root:
            h = height[node]
            height_dist[h] += 1
            total_height += h  # 累加高度
            node_count += 1  # 累加节点数
            if h > max_height:
                max_height = h

    # 计算高度平均值
    avg_height = total_height / node_count if node_count > 0 else 0

    return {
        "max_component_size": comp_sizes[max_comp],
        "largest_tree_root": max_root,
        "largest_tree_size": tree_sizes[max_root],
        "height_distribution": height_dist,
        "max_height": max_height,
        "avg_height": avg_height,  # 添加平均值返回
        "total_height": total_height,
        "node_count": node_count
    }


# ========= 绘制柱状图函数 =========
def plot_height_distribution(height_dist, avg_height):
    """
    绘制高度分布柱状图
    :param height_dist: 高度分布Counter
    :param avg_height: 高度平均值
    """
    # 准备数据
    heights = sorted(height_dist.keys())
    counts = [height_dist[h] for h in heights]

    # 创建画布
    fig, ax = plt.subplots(figsize=(12, 6))

    # 绘制柱状图
    bars = ax.bar(heights, counts, color='#2E86AB', alpha=0.8, edgecolor='black', linewidth=0.5)

    # 添加平均值线
    ax.axvline(x=avg_height, color='#E63946', linestyle='--', linewidth=2,
               label=f'平均值: {avg_height:.2f}')

    # 设置标签和标题
    ax.set_xlabel('Height值', fontsize=12, fontweight='bold')
    ax.set_ylabel('节点数量', fontsize=12, fontweight='bold')
    ax.set_title('最大树Height分布柱状图', fontsize=14, fontweight='bold', pad=20)

    # 添加数值标签
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2., height + 0.5,
                f'{int(height)}', ha='center', va='bottom', fontsize=9)

    # 设置网格
    ax.grid(axis='y', alpha=0.3, linestyle='-')

    # 添加图例
    ax.legend(loc='upper right', fontsize=10)

    # 调整布局
    plt.tight_layout()

    # 显示图表
    plt.show()


# ================= 运行 =================
if __name__ == "__main__":
    s = 16  # 建议 10~16

    print(f"正在分析 s={s} 的情况...")
    result = analyze(s)

    # 打印结果
    print("=" * 50)
    print("分析结果：")
    print("=" * 50)
    print(f"最大连通分量大小: {result['max_component_size']}")
    print(f"最大树大小: {result['largest_tree_size']}")
    print(f"最大树高度: {result['max_height']}")
    print(f"最大树Height平均值: {result['avg_height']:.2f}")

    print("\n最大树 Height 分布：")
    for h in sorted(result["height_distribution"]):
        print(f"h={h}: {result['height_distribution'][h]}")

    # 绘制柱状图
    print("\n绘制高度分布柱状图...")
    plot_height_distribution(result["height_distribution"], result["avg_height"])