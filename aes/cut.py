import sys
import hashlib
import secrets
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
    """AES加密"""
    key_len = len(key_bytes)
    if key_len not in [16, 24, 32]:
        raise ValueError("密钥长度必须为16/24/32字节（对应AES-128/192/256）")

    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return ciphertext


def aes_round_iteration(s_bits, t_rounds, keys, round_constants, input_values):
    """
    执行t轮AES迭代加密
    :param s_bits: 输入/输出的比特长度
    :param t_rounds: 迭代轮数
    :param keys: 每轮的密钥列表（长度=t_rounds）
    :param round_constants: 每轮的常数列表（长度=t_rounds）
    :param input_values: 待处理的输入值列表（整数）
    :return: 输入→输出的映射字典
    """
    if len(keys) != t_rounds or len(round_constants) != t_rounds:
        raise ValueError("密钥/轮常数数量必须等于迭代轮数t")
    if s_bits < 1 or s_bits > 128:
        raise ValueError("s_bits必须是1~128之间的整数")

    aes_block_bits = 128
    input_output_map = {}

    for input_val in input_values:
        # 初始化128比特（前s位为输入值，后128-s位补0）
        input_bits = int_to_bits(input_val, s_bits)
        current_bits = input_bits + [0] * (aes_block_bits - s_bits)

        # 逐轮迭代
        for round_idx in range(t_rounds):
            round_key = keys[round_idx]
            round_const = round_constants[round_idx]

            # 比特转16字节
            current_int = bits_to_int(current_bits)
            current_bytes = current_int.to_bytes(16, byteorder='big')

            # 轮常数异或
            current_bytes = bytes([a ^ b for a, b in zip(current_bytes, round_const)])

            # AES加密
            cipher_bytes = aes_encrypt_block(current_bytes, round_key)

            # 加密结果转回比特，仅保留前s位（后续补0）
            cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
            cipher_bits = int_to_bits(cipher_int, aes_block_bits)
            current_bits = cipher_bits[:s_bits] + [0] * (aes_block_bits - s_bits)

        # 最终输出：仅保留前s位对应的整数值
        final_output_val = bits_to_int(current_bits[:s_bits])
        input_output_map[input_val] = final_output_val

    return input_output_map


def filter_collision_outputs_after_round1(s_bits, keys, round_constants):
    """
    执行第一轮迭代，并筛选出发生碰撞的输出值
    :return: 第一轮碰撞输出值列表、第一轮完整输入→输出映射
    """
    # 执行第一轮迭代（仅1轮）
    all_inputs = range(2 ** s_bits)
    round1_io_map = aes_round_iteration(
        s_bits=s_bits,
        t_rounds=1,
        keys=keys[:1],  # 仅用第一轮密钥
        round_constants=round_constants[:1],  # 仅用第一轮常数
        input_values=all_inputs
    )

    # 统计第一轮输出的原像数（输出→输入列表）
    output_to_inputs = defaultdict(list)
    for in_val, out_val in round1_io_map.items():
        output_to_inputs[out_val].append(in_val)

    # 筛选出发生碰撞的输出值（原像数≥2）
    collision_outputs = [out_val for out_val, in_list in output_to_inputs.items() if len(in_list) >= 2]
    collision_outputs = sorted(collision_outputs)  # 排序便于查看

    return collision_outputs, round1_io_map, output_to_inputs


def analyze_output_distribution(input_output_map):
    """分析输出分布：统计唯一输出数、最大/最小原像数及对应输出"""
    output_count = defaultdict(int)
    for output_val in input_output_map.values():
        output_count[output_val] += 1

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

    return unique_outputs, max_output, max_count, min_output, min_count


if __name__ == "__main__":
    # 实验配置
    s = 10  # 输入/输出比特数
    t = 16  # 总迭代轮数

    # 16轮密钥（k1~k16，每轮16字节）
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
        bytes.fromhex("c8d7e6f504132231405968778695a4b3"),
    ]

    # 16轮常数（c1~c16，每轮16字节）
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
        bytes.fromhex("f1f2f3f4f5f6f7f8f9fafbfcfdfeff00"),
    ]

    # ========== 步骤1：执行第一轮迭代，筛选碰撞输出值 ==========
    print(f"===== 步骤1：执行第一轮迭代，筛选碰撞输出值 =====")
    collision_outputs, round1_io_map, round1_output2inputs = filter_collision_outputs_after_round1(
        s_bits=s,
        keys=keys,
        round_constants=round_constants
    )
    print(f"第一轮迭代总输入数：{2**s}")
    print(f"第一轮发生碰撞的输出值数量：{len(collision_outputs)}")

    # ========== 步骤2：用碰撞输出值作为新输入，执行剩余t-1轮迭代 ==========
    print(f"\n===== 步骤2：执行剩余{t-1}轮迭代 =====")
    # 剩余轮数用第2~16轮的密钥和常数
    remaining_io_map = aes_round_iteration(
        s_bits=s,
        t_rounds=t-1,
        keys=keys[1:],
        round_constants=round_constants[1:],
        input_values=collision_outputs
    )
    print(f"参与剩余迭代的输入数（第一轮碰撞输出数）：{len(collision_outputs)}")
    print(f"剩余迭代后得到的唯一输出数：{len(set(remaining_io_map.values()))}")

    # ========== 步骤3：执行完整t轮迭代，获取原全局最大输出 ==========
    print(f"\n===== 步骤3：执行完整{t}轮迭代，获取原全局最大输出 =====")
    full_io_map = aes_round_iteration(
        s_bits=s,
        t_rounds=t,
        keys=keys,
        round_constants=round_constants,
        input_values=range(2**s)
    )
    _, original_max_output, original_max_count, _, _ = analyze_output_distribution(full_io_map)
    print(f"原全局最大输出值：0b{bin(original_max_output)[2:].zfill(s)}（十进制：{original_max_output}）")
    print(f"原全局最大输出的原像数：{original_max_count}")

    # ========== 步骤4：验证原最大输出是否存在于筛选后的最终输出中 ==========
    print(f"\n===== 步骤4：最终验证 =====")
    filtered_final_outputs = set(remaining_io_map.values())
    if original_max_output in filtered_final_outputs:
        # 统计该值在筛选后迭代中的原像数
        filtered_count = list(remaining_io_map.values()).count(original_max_output)
        print(f"原全局最大输出值仍存在于筛选后的最终输出中")
    else:
        print(f"原全局最大输出值未出现在筛选后的最终输出中")