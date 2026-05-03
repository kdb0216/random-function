import hashlib

def prf(input_bits: str, s: int) -> str:
    """伪随机函数"""
    if len(input_bits) != s:
        raise ValueError(f"输入必须是 {s} 位")
    data = input_bits.encode('utf-8')
    h = hashlib.sha256(data).hexdigest()
    bits = bin(int(h, 16))[2:].zfill(256)[:s]
    return bits

def count_prf_image_all_inputs(s: int) -> int:
    """
    遍历 2^s 个所有可能的 s 位输入
    计算每个输入经过 prf 后的输出，统计不同输出的数量（像点个数）
    """
    output_set = set()  # 自动去重

    # 遍历 0 ~ 2^s - 1 的所有整数
    for i in range(2 ** s):
        # 转成 s 位二进制字符串（前面补 0）
        input_bits = bin(i)[2:].zfill(s)
        # 计算 prf 输出
        out = prf(input_bits, s)
        # 加入集合
        output_set.add(out)

    # 集合大小 = 像点个数
    return len(output_set)

# ===================== 测试 =====================
if __name__ == "__main__":
    s = 16  # s 位输入（s 越大，2^s 越多，计算越慢）
    image_count = count_prf_image_all_inputs(s)

    print(f"s = {s}")
    print(f"总输入数量：2^{s} = {2**s}")
    print(f"PRF 像点个数（不同输出数）：{image_count}")