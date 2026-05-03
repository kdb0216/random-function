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
    AES迭代加密核心函数（仅保留最终输入输出映射）
    :param s_bits: 输入/输出比特长度
    :param t_rounds: 迭代次数
    :param sample_size: 采样数量
    :param keys: 每轮密钥列表
    :param round_constants: 每轮常数列表
    :return: 最终输入输出映射
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

    # 执行迭代，获取最终输入输出映射
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

    return input_output_map


def get_unique_output_count(input_output_map):
    """统计最终不同输出的数量"""
    output_vals = set(input_output_map.values())
    return len(output_vals)


if __name__ == "__main__":
    # 固定输入/输出比特数（可根据需要调整）
    s = 20
    print(f"当前输入/输出比特长度：s = {s}")

    # ========== 1. 自动计算迭代次数和采样数量 ==========
    # 迭代轮数 = 2^(s/2)，需保证 s/2 为整数
    if s % 2 != 0:
        raise ValueError(f"s={s}不是偶数，无法计算2^(s/2)轮迭代（请设置偶数的s值）")
    t_rounds = 2 ** (s // 2)
    print(f"自动计算迭代次数：2^({s}/2) = {t_rounds}")

    # 采样数量 = 2^(3s/4)，需保证 3s/4 为整数
    if (3 * s) % 4 != 0:
        raise ValueError(f"s={s}无法满足3s/4为整数，无法计算2^(3s/4)采样数量（请调整s值为4的倍数）")
    sample_size = 2 ** ((3 * s) // 4)
    max_possible_sample = 2 ** s
    if sample_size > max_possible_sample:
        raise ValueError(f"采样数量{sample_size}超过最大可能值{max_possible_sample}（2^{s}）")
    print(f"自动计算采样数量：2^(3*{s}/4) = {sample_size}")

    # ========== 2. 生成密钥和轮常数 ==========
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

    # ========== 3. 执行迭代并统计最终不同输出数量 ==========
    print(f"\n开始执行：迭代次数={t_rounds}，采样数量={sample_size}")
    input_output_map = aes_round_iteration(s, t_rounds, sample_size, keys, round_constants)

    # 统计最终不同输出数量
    unique_output_count = get_unique_output_count(input_output_map)

    # ========== 4. 打印最终结果 ==========
    print(f"\n===== 最终统计结果 =====")
    print(f"输入比特长度 s = {s}")
    print(f"迭代轮数 = 2^(s/2) = {t_rounds}")
    print(f"采样数量 = 2^(3s/4) = {sample_size}")
    print(f"最终不同输出的数量：{unique_output_count}")