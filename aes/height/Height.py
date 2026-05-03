def prf(input_bits: str, s: int) -> str:
    """伪随机函数"""
    if len(input_bits) != s:
        raise ValueError(f"输入必须是 {s} 位")
    import hashlib
    data = input_bits.encode('utf-8')
    h = hashlib.md5(data).hexdigest()
    bits = bin(int(h, 16))[2:].zfill(128)[:s]
    return bits

def get_height(x: str, s: int, f, cache: dict) -> int:
    """
    计算一个点 x 的 Height：
    - 第一次到达圈上的点所需最少步数
    - 用 cache 缓存结果，避免重复计算
    """
    path = []  # 记录本次迭代路径
    current = x

    while True:
        if current in cache:
            # 遇到已知结果：整条路径的 Height 都能推算
            h = cache[current]
            for idx, node in enumerate(reversed(path)):
                cache[node] = idx + 1 + h
            return cache[x]

        if current in path:
            # 发现圈：圈上所有点 Height = 0
            circle_start_idx = path.index(current)
            for node in path[circle_start_idx:]:
                cache[node] = 0
            # 圈前路径的 Height
            for idx, node in enumerate(reversed(path[:circle_start_idx])):
                cache[node] = idx + 1
            return cache[x]

        # 继续迭代
        path.append(current)
        current = f(current, s)

def main(s: int):
    """
    遍历所有 s 位二进制串，统计 Height 分布
    """
    total = 2 ** s
    print(f"=== 开始统计 Height 分布 ===")
    print(f"s = {s}, 总状态数 = {total}\n")

    cache = {}  # 缓存：key=比特串, value=Height
    height_count = {}  # 统计每个 Height 出现次数

    # 生成所有 s 位二进制串
    for i in range(total):
        # 转成 s 位前导零补齐的比特串
        x = bin(i)[2:].zfill(s)
        h = get_height(x, s, prf, cache)
        height_count[h] = height_count.get(h, 0) + 1

    # 输出统计结果
    print("Height 分布：")
    print("Height\t个数\t占比(%)")
    print("-" * 30)
    for h in sorted(height_count.keys()):
        cnt = height_count[h]
        ratio = cnt / total * 100
        print(f"{h}\t{cnt}\t{ratio:.2f}")

    print("-" * 30)
    print(f"圈上点(Height=0)：{height_count.get(0, 0)} 个")

# ======================
# 运行程序（修改 s 即可）
# ======================
if __name__ == "__main__":
    # 建议 s ≤ 20，s=16 有 65536 个状态，几秒跑完
    main(s=16)