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


def aes_round_iteration_filtered(s_bits, t_rounds, keys, round_constants, start_filter_round, end_filter_round):
    """
    带碰撞过滤的t轮AES迭代加密
    :param s_bits: 输入/输出比特长度（s≤128，建议为8的倍数）
    :param t_rounds: 总迭代轮数
    :param keys: 每轮密钥列表 [k1, k2, ..., kt]
    :param round_constants: 轮常数列表 [c1, c2, ..., ct]
    :param start_filter_round: 从第几轮开始过滤未碰撞输入（1-based）
    :param end_filter_round: 过滤结束轮数（1-based）
    :return:
        - 最终输入输出映射
        - 每轮保留的输入数统计
        - 原始输入到每轮输出的映射字典 {原始输入: [轮1输出, 轮2输出, ..., 轮n输出]}
        - 最终输出到原始输入的映射字典 {最终输出: [原始输入1, 原始输入2, ...]}
    """
    if len(keys) != t_rounds or len(round_constants) != t_rounds:
        raise ValueError("密钥/轮常数数量必须等于迭代轮数t")
    if s_bits < 1 or s_bits > 128:
        raise ValueError("s_bits必须是1~128之间的整数")

    aes_block_bits = 128  # AES块长度
    random_sample_count = 2 ** 14
    # 初始输入集合：所有可能的s比特值
    max_input_val = 2 ** s_bits - 1
    original_inputs = set(random.sample(range(max_input_val + 1), random_sample_count))
    # 验证选取数量（防止边界情况）
    assert len(original_inputs) == random_sample_count, "随机选取的输入数量不符合要求"

    # 记录每轮保留的输入数
    round_keep_count = []
    # 核心映射：原始输入 -> 每轮输出的列表（初始化：轮0输出=原始输入）
    original_to_round_outputs = {orig_inp: [orig_inp] for orig_inp in original_inputs}
    # 当前轮处理的输入（初始为原始输入）
    current_inputs = original_inputs.copy()

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

        # 更新原始输入的轮输出列表
        for orig_inp in original_to_round_outputs:
            # 只有当原始输入的上一轮输出在当前输入中时，才更新本轮输出
            prev_output = original_to_round_outputs[orig_inp][-1]
            if prev_output in current_io_map:
                original_to_round_outputs[orig_inp].append(current_io_map[prev_output])
            else:
                # 该原始输入已被过滤，本轮输出标记为None
                original_to_round_outputs[orig_inp].append(None)

        # 统计本轮输出的碰撞情况（输出值->对应输入数）
        output_to_inputs = defaultdict(list)
        for in_val, out_val in current_io_map.items():
            output_to_inputs[out_val].append(in_val)

        # 判断是否需要过滤：仅当轮数在过滤区间内时执行
        if start_filter_round <= round_num <= end_filter_round:
            # 过滤规则：仅保留输出发生碰撞的输入（输出值对应≥2个输入）
            keep_inputs = set()
            for out_val, in_vals in output_to_inputs.items():
                if len(in_vals) >= 2:  # 碰撞：一个输出对应多个输入
                    keep_inputs.add(out_val)  # 保留产生该输出的所有输入
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

    # 构建最终输出到原始输入的映射
    final_output_to_originals = defaultdict(list)
    for orig_inp, round_outputs in original_to_round_outputs.items():
        final_output = round_outputs[-1]
        if final_output is not None:  # 只统计未被过滤的原始输入
            final_output_to_originals[final_output].append(orig_inp)

    # 构建最终的输入输出映射（当前输入->最终输出）
    final_io_map = {}
    for orig_inp, round_outputs in original_to_round_outputs.items():
        final_output = round_outputs[-1]
        if final_output is not None:
            final_io_map[orig_inp] = final_output

    return final_io_map, round_keep_count, original_to_round_outputs, final_output_to_originals


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
    s = 16  # 输入/输出比特数
    t = 16  # 总迭代轮数
    start_filter_round = 1  # 从第几轮开始过滤未碰撞输入
    end_filter_round = 2

    keys = [
               bytes.fromhex("5f8a9d7b2c4e6f1089abcdef01234567"),
               bytes.fromhex("a1b2c3d4e5f607089988776655443322"),
               bytes.fromhex("10293847566574839201aabbccddeeff"),
               bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f"),
               bytes.fromhex("4a7d9c8b0e2f1a3c5b7d9f8e6c4a2b0d"),
               bytes.fromhex("89abcdef012345675f8a9d7b2c4e6f10"),
               bytes.fromhex("9988776655443322a1b2c3d4e5f60708"),
               bytes.fromhex("9201aabbccddeeff1029384756657483"),
               bytes.fromhex("78695a4b3c2d1e0ff0e1d2c3b4a59687"),
               bytes.fromhex("0e2f1a3c5b7d9f8e4a7d9c8b6c4a2b0d"),
               bytes.fromhex("6789abcd012345ef123456789abcdef0"),
               bytes.fromhex("fedcba98765432100123456789abcdef"),
               bytes.fromhex("112233445566778899aabbccddeeff00"),
               bytes.fromhex("a0b1c2d3e4f5061728394a5b6c7d8e9f"),
               bytes.fromhex("b9876543210fedcba9876543210fedcb"),
               bytes.fromhex("c8d7e6f504132231405968778695a4b3"),  # 16
               bytes.fromhex("d7c6b5a4938271605f4e3d2c1b0a9876"),
               bytes.fromhex("e6f708192a3b4c5d6e7f8091a2b3c4d5"),
               bytes.fromhex("f5e4d3c2b1a098766554433221100f0e"),
               bytes.fromhex("0415263748596a7b8c9d0e1f20314253"),
               bytes.fromhex("132435465768798a9babcbcdcedfe0f1"),
               bytes.fromhex("2233445566778899aabbccddeeff0011"),
               bytes.fromhex("31425364758697a8b9cadbecf0e1d2c3"),
               bytes.fromhex("405162738495a6b7c8d9e0f102132435"),
               bytes.fromhex("4f5e6d7c8b9a0b1c2d3e4f5061728394"),
               bytes.fromhex("5e6d7c8b9a0b1c2d3e4f5061728394a5"),
               bytes.fromhex("6d7c8b9a0b1c2d3e4f5061728394a5b6"),
               bytes.fromhex("7c8b9a0b1c2d3e4f5061728394a5b6c7"),
               bytes.fromhex("8b9a0b1c2d3e4f5061728394a5b6c7d8"),
               bytes.fromhex("9a0b1c2d3e4f5061728394a5b6c7d8e9"),
               bytes.fromhex("0b1c2d3e4f5061728394a5b6c7d8e9fa"),
               bytes.fromhex("1c2d3e4f5061728394a5b6c7d8e9fab0"),
           ][:t]

    round_constants = [
                          bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
                          bytes.fromhex("1112131415161718191a1b1c1d1e1f20"),
                          bytes.fromhex("2122232425262728292a2b2c2d2e2f30"),
                          bytes.fromhex("3132333435363738393a3b3c3d3e3f40"),
                          bytes.fromhex("4142434445464748494a4b4c4d4e4f50"),
                          bytes.fromhex("5152535455565758595a5b5c5d5e5f60"),
                          bytes.fromhex("6162636465666768696a6b6c6d6e6f70"),
                          bytes.fromhex("7172737475767788797a7b7c7d7e7f80"),
                          bytes.fromhex("8182838485868788898a8b8c8d8e8f90"),
                          bytes.fromhex("9192939495969798999a9b9c9d9e9fa0"),
                          bytes.fromhex("a1a2a3a4a5a6a7a8a9aaabacadaeafb0"),
                          bytes.fromhex("b1b2b3b4b5b6b7b8b9babbbcbdbebfc0"),
                          bytes.fromhex("c1c2c3c4c5c6c7c8c9cacbcccdcecfd0"),
                          bytes.fromhex("d1d2d3d4d5d6d7d8d9dadbdcdddedfe0"),
                          bytes.fromhex("e1e2e3e4e5e6e7e8e9eaebecedeeeff0"),
                          bytes.fromhex("f1f2f3f4f5f6f7f8f9fafbfcfdfeff00"),  # 16
                          bytes.fromhex("00112233445566778899aabbccddeeff"),
                          bytes.fromhex("102132435465768798a9bacbdcedfe0f"),
                          bytes.fromhex("2031425364758697a8b9cadbecf0e1d2"),
                          bytes.fromhex("30415263748596a7b8c9d0e1f2031425"),
                          bytes.fromhex("405162738495a6b7c8d9e0f102132435"),
                          bytes.fromhex("5061728394a5b6c7d8e9fa0b1c2d3e4f"),
                          bytes.fromhex("60718293a4b5c6d7e8f90a1b2c3d4e5f"),
                          bytes.fromhex("708192a3b4c5d6e7f8091a2b3c4d5e6f"),
                          bytes.fromhex("8091a2b3c4d5e6f708192a3b4c5d6e7f"),
                          bytes.fromhex("90a1b2c3d4e5f60718293a4b5c6d7e8f"),
                          bytes.fromhex("a0b1c2d3e4f5061728394a5b6c7d8e9f"),
                          bytes.fromhex("b0c1d2e3f405162738495a6b7c8d9eaf"),
                          bytes.fromhex("c0d1e2f30415263748596a7b8c9daebf"),
                          bytes.fromhex("d0e1f2031425364758697a8b9c0dadcf"),
                          bytes.fromhex("e0f102132435465768798a9bac0d1e2f"),
                          bytes.fromhex("f00112233445566778899aabbccddeef"),
                      ][:t]

    # 执行带过滤的迭代
    print(f"开始执行 {t} 轮AES迭代（从第{start_filter_round}轮开始过滤未碰撞输入），输入/输出比特数：{s}")
    final_io_map, round_keep_counts, original_to_round_outputs, final_output_to_originals = aes_round_iteration_filtered(
        s, t, keys, round_constants, start_filter_round, end_filter_round
    )

    # 分析最终输出分布
    unique_outputs, max_output, max_count, min_output, min_count, hist = analyze_output_distribution(final_io_map)

    # 打印结果
    print("\n===== 每轮保留的输入数 =====")
    for round_num, count in enumerate(round_keep_counts, 1):
        print(f"第 {round_num} 轮后保留输入数：{count}")

    print("\n===== 最终输出及对应的原始输入 =====")
    # 打印每个最终输出对应的原始输入
    for final_out, original_inps in sorted(final_output_to_originals.items()):
        print(f"最终输出值: {final_out} (0b{bin(final_out)[2:].zfill(s)})")
        print(f"  对应的原始输入: {sorted(original_inps)}")
        print(f"  原始输入数量: {len(original_inps)}\n")

    # 打印统计信息
    print("\n===== 统计信息 =====")
    print(f"最终保留的原始输入总数: {len(final_io_map)}")
    print(f"不同的最终输出数量: {len(final_output_to_originals)}")
    if final_output_to_originals:
        # 找到原像最多和最少的输出
        max_originals = max(final_output_to_originals.items(), key=lambda x: len(x[1]))
        min_originals = min(final_output_to_originals.items(), key=lambda x: len(x[1]))
        print(f"原像最多的输出值: {max_originals[0]}，对应原始输入数: {len(max_originals[1])}")
        print(f"原像最少的输出值: {min_originals[0]}，对应原始输入数: {len(min_originals[1])}")

    # 可选：打印某个原始输入的完整轮输出记录（示例）
    print("\n===== 示例：前5个原始输入的每轮输出记录 =====")
    sample_originals = list(original_to_round_outputs.keys())[:5]
    for orig_inp in sample_originals:
        round_outputs = original_to_round_outputs[orig_inp]
        print(f"原始输入: {orig_inp}")
        print(f"  各轮输出: {round_outputs}")
        print(f"  最终状态: {'保留' if round_outputs[-1] is not None else '已过滤'}\n")