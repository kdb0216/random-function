import sys
import hashlib
import secrets
import random
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ===================== 通用工具函数 =====================
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


# ===================== cut321.py 核心函数 =====================
def aes_round_iteration_filtered(s_bits, t_rounds, keys, round_constants, start_filter_round, end_filter_round,
                                 filter_round):
    """
    带碰撞过滤的t轮AES迭代加密（cut321.py核心逻辑）
    :param filter_round: 指定轮数，该轮保留原像数≥2的输出对应的第三轮起始输入
    :return: 最终输入输出映射、每轮保留的输入数统计
    """
    if len(keys) != t_rounds or len(round_constants) != t_rounds:
        raise ValueError("密钥/轮常数数量必须等于迭代轮数t")
    if s_bits < 1 or s_bits > 128:
        raise ValueError("s_bits必须是1~128之间的整数")

    aes_block_bits = 128  # AES块长度
    random_sample_count = 2 ** 14
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

    # 存储第三轮开始时的输入（用于后续回溯原像）
    round3_start_inputs = None
    # 存储从第三轮开始的输出到第三轮起始输入的映射
    output_to_round3_inputs = defaultdict(list)

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

        # 保存本轮输入输出映射
        round_input_output[round_num] = current_io_map

        # 记录第三轮开始时的输入
        if round_num == 2:
            # 第二轮结束后的输出即为第三轮开始的输入
            round3_start_inputs = set(current_io_map.values())
        # 从第三轮开始，记录输出到第三轮起始输入的映射
        if filter_round>=round_num >= 3 and round3_start_inputs is not None:
            for in_val, out_val in current_io_map.items():
                # 回溯找到该输入对应的第三轮起始输入
                # 反向查找：round3输入 -> round4输入 -> ... -> 当前轮输入
                trace_val = in_val
                trace_round = round_num - 1
                while trace_round >= 3:
                    trace_val = next(k for k, v in round_input_output[trace_round].items() if v == trace_val)
                    trace_round -= 1
                # trace_val即为第三轮开始时的输入
                output_to_round3_inputs[out_val].append(trace_val)

        input_to_latest_output = current_io_map
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
        # 处理filter_round的过滤逻辑
        elif round_num == filter_round:
            # 保留原像数≥2的输出（原像为第三轮开始时的输入）
            keep_inputs = set()
            for out_val, round3_in_vals in output_to_round3_inputs.items():
                if len(round3_in_vals) >= 2:
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

    return input_to_latest_output, round_keep_count


# ===================== 321.py 核心函数 =====================
def aes_round_iteration(s_bits, t_rounds, keys, round_constants):
    """
    t轮AES迭代加密（321.py核心逻辑）
    :return: 字典 {输入值: 最终输出值}
    """
    if len(keys) != t_rounds or len(round_constants) != t_rounds:
        raise ValueError("密钥/轮常数数量必须等于迭代轮数t")
    if s_bits < 1 or s_bits > 128:
        raise ValueError("s_bits必须是1~128之间的整数")

    aes_block_bits = 128  # AES块长度
    total_inputs = 2 ** s_bits  # 所有可能的输入数量
    input_output_map = {}

    for input_val in range(total_inputs):
        # 1. 将s比特输入值转为128比特列表（不足补0）
        input_bits = int_to_bits(input_val, s_bits)  # s比特输入
        current_bits = input_bits + [0] * (aes_block_bits - s_bits)  # 补齐到128比特

        # 2. t轮迭代
        for round_idx in range(t_rounds):
            round_key = keys[round_idx]
            round_const = round_constants[round_idx]

            # 2.1 将当前128比特列表转为字节
            current_int = bits_to_int(current_bits)
            current_bytes = current_int.to_bytes(16, byteorder='big')  # 16字节=128比特

            # 2.2 轮常数混合（字节级异或）
            current_bytes = bytes([a ^ b for a, b in zip(current_bytes, round_const)])

            # 2.3 单轮AES加密
            cipher_bytes = aes_encrypt_block(current_bytes, round_key)

            # 2.4 将加密后的字节转回128比特列表，截取前s比特作为下一轮输入
            cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
            cipher_bits = int_to_bits(cipher_int, aes_block_bits)
            current_bits = cipher_bits[:s_bits] + [0] * (aes_block_bits - s_bits)  # 补齐到128比特

        # 3. 最终输出：截取前s比特转为整数
        final_output_bits = current_bits[:s_bits]
        final_output_val = bits_to_int(final_output_bits)
        input_output_map[input_val] = final_output_val

    return input_output_map


def analyze_output_distribution(input_output_map):
    """分析输出分布（增强版，兼容321.py）"""
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

    return unique_outputs, max_output, max_count, min_output, min_count, count_histogram, output_count


def filter_high_preimage_outputs(output_count, threshold):
    """筛选原像数≥阈值的输出值（321.py）"""
    high_preimage_outputs = {}
    for output_val, count in output_count.items():
        if count >= threshold:
            high_preimage_outputs[output_val] = count
    # 按原像数降序排序
    sorted_high_outputs = dict(sorted(high_preimage_outputs.items(), key=lambda x: x[1], reverse=True))
    return sorted_high_outputs


# ===================== 整合统计函数 =====================
def calculate_overlap_ratio():
    s = 16  # 输入/输出比特数
    t = 16  # 迭代轮数
    start_filter_round = 1  # cut321.py过滤起始轮数
    end_filter_round = 1  # cut321.py过滤结束轮数
    filter_round = 3

    # 公共密钥和轮常数
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
                      ][:t]

    # ===================== 步骤1：运行cut321.py逻辑 =====================
    print("===== 执行cut321.py逻辑 =====")
    cut321_io_map, round_keep_counts = aes_round_iteration_filtered(
        s_bits=s,
        t_rounds=t,
        keys=keys,
        round_constants=round_constants,
        start_filter_round=start_filter_round,
        end_filter_round=end_filter_round,
        filter_round=filter_round
    )
    # 获取cut321.py的输出值集合
    cut321_outputs = set(cut321_io_map.values())
    print(f"\ncut321.py最终输出值数量：{len(cut321_outputs)}")
    print(f"cut321.py输出值列表（前10个）：{list(cut321_outputs)[:10]}...")

    # ===================== 步骤2：运行321.py逻辑 =====================
    print("\n===== 执行321.py逻辑 =====")
    # 执行321.py的迭代逻辑
    input_output_321 = aes_round_iteration(s, t, keys, round_constants)
    # 分析输出分布
    unique_outputs, max_output, max_count, min_output, min_count, hist, output_count = analyze_output_distribution(
        input_output_321)
    # 筛选原像数≥t的输出值
    high_preimage_outputs = filter_high_preimage_outputs(output_count, threshold=t)
    high_preimage_set = set(high_preimage_outputs.keys())

    print(f"\n321.py统计结果：")
    print(f"  - 总输出值数量：{len(input_output_321)}")
    print(f"  - 唯一输出值数量：{unique_outputs}")
    print(f"  - 原像数≥{t}的输出值数量：{len(high_preimage_set)}")

    # ===================== 步骤3：计算重叠比例 =====================
    # 计算cut321的输出值中在321.py高原像集合中的数量
    overlap_count = len(cut321_outputs & high_preimage_set)
    # 计算比例
    if len(cut321_outputs) == 0:
        overlap_ratio = 0.0
    else:
        overlap_ratio = overlap_count / len(cut321_outputs) * 100

    # ===================== 输出最终统计结果 =====================
    print("\n===== 重叠比例统计结果 =====")
    print(f"cut321.py输出值总数：{len(cut321_outputs)}")
    print(f"321.py中原像数≥{t}的输出值数量：{len(high_preimage_set)}")
    print(f"两者重叠的输出值数量：{overlap_count}")
    print(f"重叠比例：{overlap_ratio:.2f}% ({overlap_count}/{len(cut321_outputs)})")

    # 输出重叠的具体值（可选）
    if overlap_count > 0:
        overlap_values = list(cut321_outputs & high_preimage_set)
        print(f"\n重叠的输出值列表：")
        for val in overlap_values[:10]:  # 仅显示前10个
            print(f"  0b{bin(val)[2:].zfill(s)} (十进制：{val})，原像数：{high_preimage_outputs[val]}")
        if len(overlap_values) > 10:
            print(f"  ... 共{len(overlap_values)}个重叠值")

    return {
        "cut321_output_count": len(cut321_outputs),
        "321_high_preimage_count": len(high_preimage_set),
        "overlap_count": overlap_count,
        "overlap_ratio": overlap_ratio
    }


if __name__ == "__main__":
    # 执行整合统计
    result = calculate_overlap_ratio()