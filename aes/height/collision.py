def prf(input_bits: str, s: int) -> str:
    """伪随机函数"""
    if len(input_bits) != s:
        raise ValueError(f"输入必须是 {s} 位")
    import hashlib
    data = input_bits.encode('utf-8')
    h = hashlib.sha1(data).hexdigest()
    bits = bin(int(h, 16))[2:].zfill(160)[:s]
    return bits


def count_collisions_n_round(s: int, n: int) -> int:
    """
    统计迭代n轮后的总碰撞数
    :param s: 比特长度
    :param n: 迭代轮数
    :return: 总碰撞次数
    """
    from collections import defaultdict
    output_map = defaultdict(int)

    # 遍历所有初始输入
    for i in range(2 ** s):
        val = bin(i)[2:].zfill(s)
        # 迭代n轮
        for _ in range(n):
            val = prf(val, s)
        # 记录最终输出
        output_map[val] += 1

    # 计算总碰撞数
    collisions = 0
    for cnt in output_map.values():
        if cnt > 1:
            collisions += cnt - 1
    return collisions


# ==================== 使用示例 ====================
if __name__ == '__main__':
    s = 20  # 比特数
    n = 128  # 迭代轮数
    print(count_collisions_n_round(s, n))