import hashlib
import random
import statistics


def prf(input_bits: str, s: int) -> str:
    """伪随机函数"""
    if len(input_bits) != s:
        raise ValueError(f"输入必须是 {s} 位")
    data = input_bits.encode('utf-8')
    h = hashlib.sha1(data).hexdigest()
    bits = bin(int(h, 16))[2:].zfill(160)[:s]
    return bits


def test_avalanche_effect(s: int, test_times: int = 1000):
    """
    测试 PRF 的雪崩效应（扩散性）
    :param s: 比特长度
    :param test_times: 测试次数
    :return: 平均比特变化率（越接近0.5越好）
    """
    flip_rates = []  # 保存每次的变化率

    print(f"🔍 开始测试 PRF 扩散性（雪崩效应）")
    print(f"📌 位长 s = {s}")
    print(f"🔄 总测试次数：{test_times}\n")

    for _ in range(test_times):
        # 1. 生成随机 s 位输入
        original = ''.join(random.choice('01') for _ in range(s))

        # 2. 随机选一位翻转
        pos = random.randint(0, s - 1)
        modified_list = list(original)
        modified_list[pos] = '1' if modified_list[pos] == '0' else '0'
        modified = ''.join(modified_list)

        # 3. 计算 PRF 输出
        out1 = prf(original, s)
        out2 = prf(modified, s)

        # 4. 统计不同比特数量
        diff_bits = sum(c1 != c2 for c1, c2 in zip(out1, out2))
        flip_rate = diff_bits / s  # 变化比例
        flip_rates.append(flip_rate)

    # 计算统计结果
    avg = statistics.mean(flip_rates)
    std = statistics.stdev(flip_rates) if test_times > 1 else 0

    print(f"✅ 测试完成！")
    print(f"📊 平均比特变化率：{avg:.2%}")
    print(f"📉 标准差：{std:.4f}")
    print(f"🎯 理想值 = 50.00% | 越接近越好")

    # 判定扩散性是否优秀
    if 0.48 <= avg <= 0.52:
        print("\n🟢 结论：扩散性 **非常好**（完美雪崩效应）")
    elif 0.45 <= avg <= 0.55:
        print("\n🟡 结论：扩散性 **良好**")
    else:
        print("\n🔴 结论：扩散性 **较差**")

    return avg


# ===================== 运行测试 =====================
if __name__ == "__main__":
    # 参数：位长s，测试次数（越大越准确）
    test_avalanche_effect(s=16, test_times=2000)