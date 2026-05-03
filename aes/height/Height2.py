import matplotlib.pyplot as plt
def prf(input_bits: str, s: int) -> str:
    """伪随机函数"""
    if len(input_bits) != s:
        raise ValueError(f"输入必须是 {s} 位")
    import hashlib
    data = input_bits.encode('utf-8')
    h = hashlib.sha1(data).hexdigest()
    bits = bin(int(h, 16))[2:].zfill(256)[:s]
    return bits

def analyze_function_graph(s: int, f):
    """
    完整分析函数迭代图：
    1. 计算所有点的 Height
    2. 找出所有圈（数量、大小、成员）
    3. 统计 Height 分布
    """
    total_nodes = 2 ** s
    visited = set()         # 已处理过的点
    height_cache = dict()   # 高度缓存
    circles = []            # 保存所有圈：圈点列表
    height_count = dict()   # Height 统计

    # 生成所有 s 位二进制串
    all_nodes = [bin(i)[2:].zfill(s) for i in range(total_nodes)]

    for node in all_nodes:
        if node in visited:
            continue

        path = []
        current = node

        # 沿着迭代路径走，直到找到已访问 / 找到圈
        while True:
            if current in visited:
                # 路径上所有点都指向已知区域，直接推导高度
                h = height_cache[current]
                for idx, p in enumerate(reversed(path)):
                    height_cache[p] = idx + 1 + h
                    visited.add(p)
                break

            if current in path:
                # 找到圈,从 current 到当前位置是圈
                idx = path.index(current)
                circle = path[idx:]
                circles.append(circle)

                # 圈上点 Height = 0
                for p in circle:
                    height_cache[p] = 0
                    visited.add(p)

                # 圈前面的尾巴节点 Height 依次 +1
                for i, p in enumerate(reversed(path[:idx])):
                    height_cache[p] = i + 1
                    visited.add(p)
                break

            # 继续迭代
            path.append(current)
            current = f(current, s)

    # 统计 Height 分布
    for h in height_cache.values():
        height_count[h] = height_count.get(h, 0) + 1

    return circles, height_count


def plot_height_distribution(height_count: dict, s: int):
    """绘制Height值分布柱状图"""
    # 准备绘图数据
    heights = sorted(height_count.keys())
    counts = [height_count[h] for h in heights]

    # 设置中文字体（避免中文乱码）
    plt.rcParams['font.sans-serif'] = ['SimHei']  # 黑体
    plt.rcParams['axes.unicode_minus'] = False

    # 创建画布
    fig, ax = plt.subplots(figsize=(12, 6))

    # 绘制柱状图
    bars = ax.bar(heights, counts, color='#1f77b4', alpha=0.8)

    # 添加数值标签
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2., height + 0.1,
                f'{int(height)}', ha='center', va='bottom', fontsize=8)

    # 设置标题和轴标签
    ax.set_title(f'Height值分布柱状图 (s={s})', fontsize=14, fontweight='bold')
    ax.set_xlabel('Height值', fontsize=12)
    ax.set_ylabel('个数', fontsize=12)

    # 设置网格
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    # 调整布局
    plt.tight_layout()

    # 显示图表
    plt.show()

def main(s: int):

    # 执行分析
    circles, height_count = analyze_function_graph(s, prf)

    # ====================== 输出圈信息 ======================
    print(f"\n 圈个数：{len(circles)} \n")
    for i, circle in enumerate(circles, 1):
        print(f"【第 {i} 个圈】大小 = {len(circle)}")
        print(f"  成员：{circle}\n")

    # ====================== 输出 Height 分布 ======================
    print("\n" + "=" * 60)
    print("Height 分布统计")
    print("=" * 60)
    print("Height\t个数\t占比(%)")
    print("-" * 40)
    total = 2**s
    for h in sorted(height_count.keys()):
        cnt = height_count[h]
        ratio = cnt / total * 100
        print(f"{h}\t{cnt}\t{ratio:.2f}")

    print("-" * 40)
    print(f"圈上点总数：{height_count.get(0, 0)}")
    print(f"树上点总数：{total - height_count.get(0, 0)}")

    plot_height_distribution(height_count, s)

# ====================== 运行 ======================
if __name__ == "__main__":
    main(s=16)