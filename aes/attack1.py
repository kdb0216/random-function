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


def aes_round_iteration_filtered_custom(s_bits, t_total, t_prime, keys, round_constants):
    """
    自定义带碰撞过滤的AES迭代加密：
    - 遍历i从1到t_total-t_prime轮作为起始轮
    - 第i轮遍历2^s个输入，i+1/i+2轮过滤碰撞，i+t_prime轮结束并记录输出集合
    :param s_bits: 输入/输出比特长度（s≤128，建议为8的倍数）
    :param t_total: 总迭代轮数t
    :param t_prime: 自定义参数t'
    :param keys: 每轮密钥列表 [k1, k2, ..., kt]
    :param round_constants: 轮常数列表 [c1, c2, ..., ct]
    :return: 输出集合列表（共t_total-t_prime个）、每轮保留数统计
    """
    if len(keys) < t_total or len(round_constants) < t_total:
        raise ValueError("密钥/轮常数数量必须≥总迭代轮数t_total")
    if s_bits < 1 or s_bits > 128:
        raise ValueError("s_bits必须是1~128之间的整数")
    if t_prime < 2 or t_prime >= t_total:
        raise ValueError(f"t'必须满足 2 ≤ t' < {t_total}（需保证t-t' ≥1）")

    max_start_round = t_total - t_prime  # 最大起始轮i
    if max_start_round < 1:
        raise ValueError(f"t-t'必须≥1，请调整t'（当前t={t_total}, t'={t_prime}）")

    aes_block_bits = 128
    output_sets = []  # 存储每个起始轮i对应的最终输出集合
    all_round_stats = []  # 存储所有轮次的保留数统计
    random_sample_count = 2 ** (s_bits - t_prime)

    # 遍历每个起始轮i（1-based）
    for start_i in range(1, max_start_round + 1):
        print(f"\n========== 开始处理起始轮 i = {start_i} ==========")
        end_i = start_i + t_prime - 1  # 结束轮i+t'-1（即i+t'轮结束）
        print(f"起始轮i={start_i}，结束轮={end_i}（i+t'-1）")

        # 初始输入集合：所有可能的s比特值（2^s个）
        max_input_val = 2 ** s_bits - 1
        current_inputs = set(random.sample(range(max_input_val + 1), random_sample_count))
        # 验证选取数量（防止边界情况）
        assert len(current_inputs) == random_sample_count, "随机选取的输入数量不符合要求"
        round_stats = []  # 记录本轮起始的各轮保留数
        input_to_latest_output = {inp: inp for inp in current_inputs}

        # 执行从start_i到end_i的迭代
        for round_offset in range(t_prime):
            round_num = start_i + round_offset  # 当前轮数（1-based）
            round_idx = round_num - 1  # 转换为0-based索引
            round_key = keys[round_idx]
            round_const = round_constants[round_idx]

            print(f"执行轮数 {round_num}（起始轮{start_i}的第{round_offset + 1}步），当前输入数：{len(current_inputs)}")

            # 本轮迭代：处理当前保留的输入
            current_io_map = {}
            for input_val in current_inputs:
                # 1. s比特转128比特（补0）
                input_bits = int_to_bits(input_val, s_bits)
                current_bits = input_bits + [0] * (aes_block_bits - s_bits)

                # 2. 本轮处理逻辑
                current_int = bits_to_int(current_bits)
                current_bytes = current_int.to_bytes(16, byteorder='big')
                # 轮常数混合（字节级异或）
                current_bytes = bytes([a ^ b for a, b in zip(current_bytes, round_const)])
                # 单轮AES加密
                cipher_bytes = aes_encrypt_block(current_bytes, round_key)
                # 转回比特列表，截取前s比特作为输出
                cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
                cipher_bits = int_to_bits(cipher_int, aes_block_bits)
                output_bits = cipher_bits[:s_bits]
                output_val = bits_to_int(output_bits)

                current_io_map[input_val] = output_val

            input_to_latest_output = current_io_map
            # 统计输出碰撞情况
            output_to_inputs = defaultdict(list)
            for in_val, out_val in current_io_map.items():
                output_to_inputs[out_val].append(in_val)

            # 过滤规则：仅i+1、i+2轮（即start_i+1、start_i+2）保留碰撞输入
            filter_rounds = [start_i + 1]
            if round_num in filter_rounds:
                # 保留输出碰撞的输入（输出对应≥2个输入）
                keep_inputs = set()
                for out_val, in_vals in output_to_inputs.items():
                    if len(in_vals) >= 2:
                        keep_inputs.add(out_val)  # 保留碰撞的输入（原输入，非输出）
                current_inputs = keep_inputs
            else:
                # 其他轮次保留所有输出作为下一轮输入
                current_inputs = set(current_io_map.values())

            round_stats.append(len(current_inputs))
            # 输入为空则提前终止
            if not current_inputs:
                print(f"轮数 {round_num} 后无保留输入，提前终止当前起始轮{start_i}的迭代")
                break

        # 记录当前起始轮i的最终输出集合（end_i轮的输出值）
        final_outputs = set(input_to_latest_output.values())
        output_sets.append(final_outputs)
        all_round_stats.append(round_stats)
        print(f"起始轮{start_i}的最终输出集合大小：{len(final_outputs)}")

    return output_sets, all_round_stats


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
    s = 20  # 输入/输出比特数
    t_total = 32  # 总迭代轮数t
    t_prime = 8  # 自定义参数t'（步长）
    max_start_round = t_total - t_prime  # 起始轮i的最大值（1~max_start_round）

    # 密钥列表（保持原代码的32个密钥）
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
    ]

    round_constants = [
        bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
        bytes.fromhex("1112131415161718191a1b1c1d1e1f20"),
        bytes.fromhex("2122232425262728292a2b2c2d2e2f30"),
        bytes.fromhex("3132333435363738393a3b3c3d3e3f40"),
        bytes.fromhex("4142434445464748494a4b4c4d4e4f50"),
        bytes.fromhex("5152535455565758595a5b5c5d5e5f60"),
        bytes.fromhex("6162636465666768696a6b6c6d6e6f70"),
        bytes.fromhex("7172737475767778797a7b7c7d7e7f80"),
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
    ]

    # 执行自定义迭代逻辑
    print(f"总迭代轮数t={t_total}，t'={t_prime}，起始轮数范围：1~{max_start_round}")
    output_sets, round_stats = aes_round_iteration_filtered_custom(
        s_bits=s,
        t_total=t_total,
        t_prime=t_prime,
        keys=keys,
        round_constants=round_constants
    )

    # 打印最终结果
    print("\n===== 所有起始轮的输出集合结果 =====")
    for idx, (start_i, output_set) in enumerate(zip(range(1, max_start_round + 1), output_sets), 1):
        print(f"起始轮i={start_i}：输出集合大小={len(output_set)}，输出值列表={sorted(list(output_set))}")

    # 打印每轮保留数统计
    print("\n===== 每轮保留输入数统计 =====")
    for idx, (start_i, stats) in enumerate(zip(range(1, max_start_round + 1), round_stats), 1):
        print(f"起始轮i={start_i}：各轮保留数={stats}")