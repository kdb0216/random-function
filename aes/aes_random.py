import sys
import hashlib
import random
import math
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def int_to_bits(n, bit_length):
    """将整数转为固定长度的比特列表，不足补0"""
    bin_str = bin(n)[2:].zfill(bit_length)
    return [int(bit) for bit in bin_str]


def bits_to_int(bit_list):
    """将比特列表转为整数"""
    bin_str = ''.join(str(bit) for bit in bit_list)
    return int(bin_str, 2) if bin_str else 0


def aes_encrypt_block(plaintext_bytes, key_bytes):
    """AES加密（ECB模式，128/192/256位密钥兼容）"""
    key_len = len(key_bytes)
    if key_len not in [16, 24, 32]:
        raise ValueError("密钥长度必须为16/24/32字节（对应AES-128/192/256）")

    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return ciphertext


def aes_round_iteration(s_bits, t_rounds, sample_size, keys, round_constants):
    """
    AES迭代加密核心函数
    :param s_bits: 输入/输出比特长度
    :param t_rounds: 迭代次数（直接输入）
    :param sample_size: 采样数量（直接输入）
    :param keys: 每轮密钥列表
    :param round_constants: 每轮常数列表
    :return: 最终输入输出映射, 每轮统计结果列表
    """
    # 核心参数校验
    if len(keys) != t_rounds or len(round_constants) != t_rounds:
        raise ValueError(f"密钥/轮常数数量必须等于迭代次数{t_rounds}")
    if s_bits < 1 or s_bits > 128:
        raise ValueError("输入/输出比特数必须是1~128之间的整数")

    max_possible_inputs = 2 ** s_bits
    if sample_size < 1 or sample_size > max_possible_inputs:
        raise ValueError(f"采样数量必须在1~{max_possible_inputs}之间（当前s={s_bits}，最大输入数={max_possible_inputs}）")

    aes_block_bits = 128  # AES固定块长度128比特
    # 随机选取指定数量的不重复输入值
    max_input_val = max_possible_inputs - 1
    sampled_inputs = random.sample(range(max_input_val + 1), sample_size)
    sampled_inputs.sort()  # 排序便于后续查看

    # ========== 第一步：执行迭代，获取最终输入输出映射 ==========
    input_output_map = {}
    for input_val in sampled_inputs:
        # 输入值补全为128比特
        input_bits = int_to_bits(input_val, s_bits)
        current_bits = input_bits + [0] * (aes_block_bits - s_bits)

        # 逐轮迭代加密
        for round_idx in range(t_rounds):
            round_key = keys[round_idx]
            round_const = round_constants[round_idx]

            # 比特转字节（16字节=128比特）
            current_int = bits_to_int(current_bits)
            current_bytes = current_int.to_bytes(16, byteorder='big')

            # 轮常数异或混合
            current_bytes = bytes([a ^ b for a, b in zip(current_bytes, round_const)])

            # AES加密
            cipher_bytes = aes_encrypt_block(current_bytes, round_key)

            # 加密结果转回比特，截取前s比特作为下一轮输入
            cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
            cipher_bits = int_to_bits(cipher_int, aes_block_bits)
            current_bits = cipher_bits[:s_bits] + [0] * (aes_block_bits - s_bits)

        # 记录最终输出
        final_output_val = bits_to_int(current_bits[:s_bits])
        input_output_map[input_val] = final_output_val

    # ========== 第二步：重新迭代，记录每轮输出并统计 ==========
    round_outputs = [{} for _ in range(t_rounds)]  # 每轮{输入值: 输出值}
    for input_val in sampled_inputs:
        input_bits = int_to_bits(input_val, s_bits)
        current_bits = input_bits + [0] * (aes_block_bits - s_bits)

        for round_idx in range(t_rounds):
            round_key = keys[round_idx]
            round_const = round_constants[round_idx]

            # 执行本轮加密（逻辑同第一步）
            current_int = bits_to_int(current_bits)
            current_bytes = current_int.to_bytes(16, byteorder='big')
            current_bytes = bytes([a ^ b for a, b in zip(current_bytes, round_const)])
            cipher_bytes = aes_encrypt_block(current_bytes, round_key)
            cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
            cipher_bits = int_to_bits(cipher_int, aes_block_bits)
            current_bits = cipher_bits[:s_bits] + [0] * (aes_block_bits - s_bits)

            # 记录本轮输出值
            round_output_val = bits_to_int(current_bits[:s_bits])
            round_outputs[round_idx][input_val] = round_output_val

    # 生成每轮统计数据
    round_stats_list = []
    for round_idx in range(t_rounds):
        output_count = defaultdict(int)
        for output_val in round_outputs[round_idx].values():
            output_count[output_val] += 1

        round_stats_list.append({
            'round': round_idx + 1,  # 轮数从1开始计数
            'unique_outputs': len(output_count),  # 本轮不同输出个数
            'output_count': dict(output_count),  # 输出值: 原像数
            'input_output': round_outputs[round_idx]
        })

    return input_output_map, round_stats_list


def analyze_output_distribution(input_output_map):
    """分析最终输出分布：不同输出数、最大/最小原像数"""
    output_count = defaultdict(int)
    for output_val in input_output_map.values():
        output_count[output_val] += 1

    unique_outputs = len(output_count)
    max_count = max(output_count.values()) if output_count else 0
    max_output = max(output_count, key=output_count.get) if output_count else None
    min_count = min(output_count.values()) if output_count else 0
    min_output = min(output_count, key=output_count.get) if output_count else None

    return unique_outputs, max_output, max_count, min_output, min_count


if __name__ == "__main__":
    # 固定输入/输出比特数（可根据需要调整）
    s = 16
    print(f"当前输入/输出比特长度：s = {s}（最大可能输入数：{2 ** s}）")

    # ========== 1. 输入迭代次数 ==========
    while True:
        try:
            t_input = input("\n请输入迭代次数（正整数）：")
            t_rounds = int(t_input)
            if t_rounds < 1:
                print("迭代次数必须≥1，请重新输入！")
                continue
            break
        except ValueError:
            print("输入无效，请输入有效的正整数！")

    # ========== 2. 输入采样数量 ==========
    max_sample_size = 2 ** s
    while True:
        try:
            sample_input = input(f"请输入采样数量（1~{max_sample_size}之间的整数）：")
            sample_size = int(sample_input)
            if sample_size < 1 or sample_size > max_sample_size:
                print(f"采样数量必须在1~{max_sample_size}之间，请重新输入！")
                continue
            break
        except ValueError:
            print("输入无效，请输入有效的正整数！")

    # ========== 3. 生成密钥和轮常数 ==========
    # 为每轮迭代生成16字节随机密钥（AES-128）
    keys = []
    for _ in range(t_rounds):
        key_bytes = bytes([random.randint(0, 255) for _ in range(16)])
        keys.append(key_bytes)

    # 为每轮迭代生成16字节随机轮常数
    round_constants = []
    for _ in range(t_rounds):
        const_bytes = bytes([random.randint(0, 255) for _ in range(16)])
        round_constants.append(const_bytes)

    # ========== 4. 执行迭代并统计 ==========
    print(f"\n开始执行：迭代次数={t_rounds}，采样数量={sample_size}")
    input_output, round_stats = aes_round_iteration(s, t_rounds, sample_size, keys, round_constants)

    # ========== 5. 打印每轮统计结果 ==========
    print(f"\n===== 每轮迭代统计结果（s={s}比特，采样{sample_size}个输入） =====")
    # 初始化求和列表：第0轮（输入）数量=采样数量
    sum_unique_counts = [sample_size]
    for stats in round_stats:
        round_num = stats['round']
        unique_outputs = stats['unique_outputs']
        output_count = stats['output_count']

        max_count = max(output_count.values()) if output_count else 0
        min_count = min(output_count.values()) if output_count else 0

        print(f"\n第 {round_num} 轮：")
        print(f"  - 不同输出个数：{unique_outputs}")
        print(f"  - 原像最多的输出数：{max_count}")
        print(f"  - 原像最少的输出数：{min_count}")

        # 收集第1~t-1轮数据用于求和
        if round_num < t_rounds:
            sum_unique_counts.append(unique_outputs)

    # ========== 6. 打印求和及最终结果 ==========
    # total_sum = sum(sum_unique_counts)
    # unique_outputs, max_output, max_count, min_output, min_count = analyze_output_distribution(input_output)
    #
    # print(f"\n===== 核心结果汇总 =====")
    # print(f"1. 计算复杂度：{total_sum}")
    # print(f"2. 最终迭代结果（{t_rounds}轮后）：")
    # print(f"   - 不同输出数量：{unique_outputs}")
    # if max_output is not None:
    #     print(f"   - 原像最多的输出值：0b{bin(max_output)[2:].zfill(s)}（十进制：{max_output}），原像数：{max_count}")
    # if min_output is not None:
    #     print(f"   - 原像最少的输出值：0b{bin(min_output)[2:].zfill(s)}（十进制：{min_output}），原像数：{min_count}")