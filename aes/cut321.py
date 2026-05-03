import sys
import hashlib
import secrets
import random
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def int_to_bits(n, bit_length):
    """将整数转为固定长度的比特列表（高位在前），不足补0"""
    bin_str = bin(n)[2:].zfill(bit_length)
    return [int(bit) for bit in bin_str]


def bits_to_int(bit_list):
    """将比特列表转为整数（高位在前）"""
    bin_str = ''.join(str(bit) for bit in bit_list)
    return int(bin_str, 2) if bin_str else 0


def aes_encrypt_block(plaintext_bytes, key_bytes):
    """AES加密（完整流程）"""
    key_len = len(key_bytes)
    if key_len not in [16, 24, 32]:
        raise ValueError("密钥长度必须为16/24/32字节（对应AES-128/192/256）")

    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return ciphertext


def aes_round_iteration_filtered(s_bits, t_rounds, keys, round_constants, start_filter_round=1):
    """
    带碰撞过滤的t轮AES迭代加密
    :param s_bits: 输入/输出比特长度（s≤128，建议为8的倍数）
    :param t_rounds: 总迭代轮数
    :param keys: 每轮密钥列表 [k1, k2, ..., kt]
    :param round_constants: 轮常数列表 [c1, c2, ..., ct]
    :param start_filter_round: 从第几轮开始过滤未碰撞输入（1-based）
    :return: 最终输入输出映射、每轮保留的输入数统计
    """
    if len(keys) != t_rounds or len(round_constants) != t_rounds:
        raise ValueError("密钥/轮常数数量必须等于迭代轮数t")
    if s_bits < 1 or s_bits > 128:
        raise ValueError("s_bits必须是1~128之间的整数")
    # if start_filter_round < 1 or start_filter_round > t_rounds:
    #     raise ValueError(f"start_filter_round必须在1~{t_rounds}之间")

    aes_block_bits = 128  # AES块长度
    random_sample_count = 2 ** s_bits
    # 初始输入集合：所有可能的s比特值
    max_input_val = 2 ** s_bits - 1
    current_inputs = set(random.sample(range(max_input_val + 1), random_sample_count))
    # 验证选取数量（防止边界情况）
    assert len(current_inputs) == random_sample_count, "随机选取的输入数量不符合要求"
    # 记录每轮保留的输入数
    round_keep_count = []
    # 存储每轮输入->输出的映射（用于过滤）
    round_input_output = {}
    input_to_latest_output = {inp: inp for inp in current_inputs}  # 初始输出=输入

    for round_idx in range(t_rounds):
        round_num = round_idx + 1  # 1-based轮数
        round_key = keys[round_idx]
        round_const = round_constants[round_idx]

        print(f"执行第 {round_num} 轮迭代，当前输入数：{len(current_inputs)}")

        # 本轮迭代：仅处理当前保留的输入
        current_io_map = {}
        for input_val in current_inputs:
            # 1. 将s比特输入值转为128比特列表（不足补0）
            input_bits = int_to_bits(input_val, s_bits)
            current_bits = input_bits + [0] * (aes_block_bits - s_bits)

            # 2. 本轮处理逻辑
            # 2.1 转为字节
            current_int = bits_to_int(current_bits)
            current_bytes = current_int.to_bytes(16, byteorder='big')
            # 2.2 轮常数混合（字节级异或）
            current_bytes = bytes([a ^ b for a, b in zip(current_bytes, round_const)])
            # 2.3 单轮AES加密
            cipher_bytes = aes_encrypt_block(current_bytes, round_key)
            # 2.4 转回比特列表，截取前s比特作为本轮输出
            cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
            cipher_bits = int_to_bits(cipher_int, aes_block_bits)
            output_bits = cipher_bits[:s_bits]
            output_val = bits_to_int(output_bits)

            current_io_map[input_val] = output_val

        input_to_latest_output = current_io_map
        # 保存本轮输入输出映射
        round_input_output[round_num] = current_io_map
        # 统计本轮输出的碰撞情况（输出值->对应输入数）
        output_to_inputs = defaultdict(list)
        for in_val, out_val in current_io_map.items():
            output_to_inputs[out_val].append(in_val)

        # 判断是否需要过滤：仅当轮数≥起始过滤轮数时执行
        if start_filter_round <= round_num <= end_filter_round:
            # 过滤规则：仅保留输出发生碰撞的输入（输出值对应≥2个输入）
            keep_inputs = set()
            for out_val, in_vals in output_to_inputs.items():
                if len(in_vals) >= 2:  # 碰撞：一个输出对应多个输入
                    keep_inputs.add(out_val)
            current_inputs = keep_inputs
        else:
            # 未到过滤轮数：保留所有输入
            current_inputs = set(current_io_map.values())

        # 记录本轮保留的输入数
        round_keep_count.append(len(current_inputs))
        # 如果输入为空，提前终止
        if not current_inputs:
            print(f"第 {round_num} 轮后无保留输入，提前终止迭代")
            break

    #final_io_map = {inp: input_to_latest_output[inp] for inp in current_inputs}

    return current_io_map, round_keep_count


def analyze_output_distribution(input_output_map):
    """分析输出分布：统计不同输出数、原像最多/最少的输出及数量"""
    if not input_output_map:
        return 0, None, 0, None, float('inf'), defaultdict(int)

    output_count = defaultdict(int)
    for output_val in input_output_map.values():
        output_count[output_val] += 1

    count_histogram = defaultdict(int)
    for cnt in output_count.values():
        count_histogram[cnt] += 1

    unique_outputs = len(output_count)
    max_count = 0
    max_output = None
    for output_val, count in output_count.items():
        if count > max_count:
            max_count = count
            max_output = output_val

    min_count = float('inf')
    min_output = None
    for output_val, count in output_count.items():
        if count < min_count:
            min_count = count
            min_output = output_val

    return unique_outputs, max_output, max_count, min_output, min_count, count_histogram


if __name__ == "__main__":
    # 配置参数
    s = 18 # 输入/输出比特数
    t = 128  # 总迭代轮数
    start_filter_round = 1  # 从第几轮开始过滤未碰撞输入
    end_filter_round = 3

    keys = [secrets.token_bytes(16) for _ in range(t)]
    round_constants = [secrets.token_bytes(16) for _ in range(t)]

    # 执行带过滤的迭代
    print(f"开始执行 {t} 轮AES迭代（从第{start_filter_round}轮开始过滤未碰撞输入），输入/输出比特数：{s}")
    final_io_map, round_keep_counts = aes_round_iteration_filtered(s, t, keys, round_constants, start_filter_round)

    # 分析最终输出分布
    unique_outputs, max_output, max_count, min_output, min_count, hist = analyze_output_distribution(final_io_map)

    # 打印结果
    print("\n===== 每轮保留的输入数 =====")
    for round_num, count in enumerate(round_keep_counts, 1):
        print(f"第 {round_num} 轮后保留输入数：{count}")


    print("\n===== 最终输出值列表 =====")
    # 提取所有输出值并打印
    output_values = list(final_io_map.values())
    print(output_values)

    output_count = defaultdict(int)
    for output_val in output_values:
        output_count[output_val] += 1

    unique_outputs = len(output_count)
    print(unique_outputs)
