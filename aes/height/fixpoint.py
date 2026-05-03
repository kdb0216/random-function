def prf(input_bits: str, s: int) -> str:
    """伪随机函数"""
    if len(input_bits) != s:
        raise ValueError(f"输入必须是 {s} 位")
    import hashlib
    data = input_bits.encode('utf-8')
    h = hashlib.md5(data).hexdigest()
    bits = bin(int(h, 16))[2:].zfill(128)[:s]
    return bits


def count_fixed_points_n(s: int, n: int) -> int:
    """
    统计迭代n次后的不动点数量：f^n(x) = x
    返回：满足条件的x的个数
    """
    count = 0
    total = 2 ** s

    for i in range(total):
        x = bin(i)[2:].zfill(s)
        current = x

        # 迭代 n 轮
        for _ in range(n):
            current = prf(current, s)

        # 判断是否是不动点
        if current == x:
            count += 1

    return count


# ==================== 使用 ====================
if __name__ == '__main__':
    s = 16  # 比特长度
    n = 14  # 迭代次数
    print(count_fixed_points_n(s, n))