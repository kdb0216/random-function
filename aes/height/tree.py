import matplotlib.pyplot as plt
import hashlib

def prf(input_bits: str, s: int) -> str:
    if len(input_bits) != s:
        raise ValueError(f"输入必须是 {s} 位")
    data = input_bits.encode('utf-8')
    h = hashlib.md5(data).hexdigest()
    bits = bin(int(h, 16))[2:].zfill(128)[:s]
    return bits

def get_path(x, s, f, max_steps=10000):
    path = []
    cur = x
    while cur not in path and len(path) < max_steps:
        path.append(cur)
        cur = f(cur, s)
    return path, cur

def analyze_max_circle_predecessor_tree(s: int, f):
    print(f"正在分析 s={s}，寻找最大圈及其尾巴树...\n")

    # 1. 遍历所有点，找到所有圈 + 计算每个点 Height
    visited = set()
    circles = []
    node_height = {}
    node_circle = {}
    total = 2**s
    all_nodes = [bin(i)[2:].zfill(s) for i in range(total)]

    for node in all_nodes:
        if node in visited:
            continue
        path, cur = get_path(node, s, f)
        if cur in path:
            idx = path.index(cur)
            circle = path[idx:]
            circles.append(circle)
            for p in circle:
                node_height[p] = 0
                node_circle[p] = circle
                visited.add(p)
            for i, p in enumerate(reversed(path[:idx])):
                node_height[p] = i + 1
                node_circle[p] = circle
                visited.add(p)

    # 2. 找到最大圈
    max_circle = max(circles, key=lambda c: len(c))
    max_circle_set = set(max_circle)
    print(f"✅ 最大圈大小 = {len(max_circle)}")
    print(f"   圈成员: {max_circle}\n")

    # 3. 找到所有直接/间接连入最大圈的尾巴起点
    tail_root_candidates = []
    for node in all_nodes:
        if node in max_circle_set:
            continue
        nxt = f(node, s)
        if nxt in max_circle_set or node_circle.get(nxt) == max_circle:
            tail_root_candidates.append(node)

    # 4. 找到最长的主干尾巴
    max_tail_len = -1
    main_tail = None
    for t in tail_root_candidates:
        path, _ = get_path(t, s, f)
        clen = 0
        for p in path:
            if p in max_circle_set:
                break
            clen += 1
        if clen > max_tail_len:
            max_tail_len = clen
            main_tail = t

    # 5. 生成主干尾巴路径
    main_tail_path = []
    cur = main_tail
    while cur not in max_circle_set:
        main_tail_path.append(cur)
        cur = f(cur, s)

    # 6. 收集：所有汇入这条主干尾巴的点（你要的树）
    target_tree_nodes = set()
    for node in all_nodes:
        if node in max_circle_set:
            continue
        path, _ = get_path(node, s, f)
        for p in path:
            if p in main_tail_path:
                target_tree_nodes.add(node)
                break

    # 7. 统计 Height 分布
    height_dist = {}
    for u in target_tree_nodes:
        h = node_height[u]
        height_dist[h] = height_dist.get(h, 0) + 1

    # 输出结果
    print(f"目标树（主干尾巴 + 所有汇入尾巴的点）总数：{len(target_tree_nodes)}")
    print(f"最长主干尾巴长度：{len(main_tail_path)}")
    print("-" * 50)
    print("目标树 Height 分布：")
    print("Height\t个数")
    print("-" * 20)
    for h in sorted(height_dist):
        print(f"{h}\t{height_dist[h]}")
    print("-" * 50)

    # 绘图
    plt.rcParams['font.sans-serif'] = ['SimHei']
    plt.figure(figsize=(10, 5))
    xs = sorted(height_dist.keys())
    ys = [height_dist[x] for x in xs]
    plt.bar(xs, ys, color='#ff6600', alpha=0.85)
    plt.title(f"最大圈 - 主干树 Height 分布 | s={s}", fontsize=14)
    plt.xlabel("Height", fontsize=12)
    plt.ylabel("节点个数", fontsize=12)
    plt.grid(axis='y', alpha=0.3)
    plt.show()

# ====================== 运行（已补齐参数） ======================
if __name__ == "__main__":
    analyze_max_circle_predecessor_tree(s=12, f=prf)