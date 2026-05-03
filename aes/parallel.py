import sys
import hashlib
import random
import math
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from multiprocessing import Pool, cpu_count
import time


# 工具函数（保持不变）
def int_to_bits(n, bit_length):
    bin_str = bin(n)[2:].zfill(bit_length)
    return [int(bit) for bit in bin_str]


def bits_to_int(bit_list):
    bin_str = ''.join(str(bit) for bit in bit_list)
    return int(bin_str, 2) if bin_str else 0


def aes_encrypt_block(plaintext_bytes, key_bytes):
    """优化版AES加密，更快更稳定"""
    key_len = len(key_bytes)
    if key_len not in [16, 24, 32]:
        raise ValueError("密钥长度必须为16/24/32字节（对应AES-128/192/256）")
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext_bytes) + encryptor.finalize()


# ========== 核心：单个输入的处理函数（供多进程调用） ==========
def process_single_input(args):
    """
    单个进程处理一个输入值的完整迭代加密
    :param args: (input_val, s_bits, t_rounds, keys, round_constants)
    :return: (input_val, final_output_val)
    """
    try:
        input_val, s_bits, t_rounds, keys, round_constants = args
        aes_block_bits = 128

        # 初始化输入比特（补全128位）
        input_bits = int_to_bits(input_val, s_bits)
        current_bits = input_bits + [0] * (aes_block_bits - s_bits)

        # 逐轮迭代加密（核心逻辑不变）
        for round_idx in range(t_rounds):
            round_key = keys[round_idx]
            round_const = round_constants[round_idx]

            # 比特转字节
            current_int = bits_to_int(current_bits)
            current_bytes = current_int.to_bytes(16, byteorder='big')

            # 轮常数异或
            current_bytes = bytes([a ^ b for a, b in zip(current_bytes, round_const)])

            # AES加密
            cipher_bytes = aes_encrypt_block(current_bytes, round_key)

            # 字节转回比特，截取前s位
            cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
            cipher_bits = int_to_bits(cipher_int, aes_block_bits)
            current_bits = cipher_bits[:s_bits] + [0] * (aes_block_bits - s_bits)

        final_output_val = bits_to_int(current_bits[:s_bits])
        return (input_val, final_output_val)
    except Exception as e:
        print(f"处理输入值 {input_val} 时出错：{e}")
        return (input_val, None)


# ========== 并行执行主函数（适配14核） ==========
def parallel_aes_calculation(s):
    """
    并行执行AES迭代计算，适配14核CPU
    :param s: 输入/输出比特长度
    :return: 不同输出的数量
    """
    # 1. 计算迭代轮数和采样数量（按你的要求）
    if s % 2 != 0:
        raise ValueError(f"s={s}不是偶数，无法计算2^(s/2)轮迭代")
    t_rounds = 2 ** (s // 2)
    print(f"迭代轮数：2^({s}/2) = {t_rounds}")

    if (3 * s) % 4 != 0:
        raise ValueError(f"s={s}无法满足3s/4为整数，请设置s为4的倍数（如32、40、48）")
    sample_size = 2 ** ((3 * s) // 4)
    max_possible_sample = 2 ** s
    if sample_size > max_possible_sample:
        raise ValueError(f"采样数量{sample_size}超过最大可能值{max_possible_sample}")
    print(f"采样数量：2^(3*{s}/4) = {sample_size}")

    # 2. 预生成密钥和轮常数（全局生成，避免进程重复生成）
    print("生成密钥和轮常数...")
    keys = []
    for _ in range(t_rounds):
        key_bytes = bytes([random.randint(0, 255) for _ in range(16)])
        keys.append(key_bytes)

    round_constants = []
    for _ in range(t_rounds):
        const_bytes = bytes([random.randint(0, 255) for _ in range(16)])
        round_constants.append(const_bytes)

    # 3. 生成采样输入列表
    print("生成采样输入列表...")
    max_input_val = max_possible_sample - 1
    sampled_inputs = random.sample(range(max_input_val + 1), sample_size)

    # 4. 并行处理（核心：用14个进程）
    print(f"启动 {cpu_count()} 个进程（你的CPU有14核）...")
    start_time = time.time()

    # 构造任务参数
    task_args = [(val, s, t_rounds, keys, round_constants) for val in sampled_inputs]

    # 启动进程池（限制为14个进程，避免超线程过载）
    with Pool(processes=14) as pool:
        results = pool.map(process_single_input, task_args)

    # 5. 整理结果，过滤错误数据
    input_output_map = {}
    for input_val, output_val in results:
        if output_val is not None:
            input_output_map[input_val] = output_val

    # 6. 统计不同输出数量
    unique_output_count = len(set(input_output_map.values()))
    end_time = time.time()

    # 打印结果
    print(f"\n===== 最终结果 =====")
    print(f"输入比特长度 s = {s}")
    print(f"迭代轮数 = {t_rounds}")
    print(f"采样数量 = {sample_size}")
    print(f"有效处理的输入数 = {len(input_output_map)}")
    print(f"最终不同输出的数量 = {unique_output_count}")
    print(f"总耗时 = {end_time - start_time:.2f} 秒")
    print(f"平均每个采样耗时 = {(end_time - start_time) / sample_size:.6f} 秒")

    return unique_output_count


# ========== 执行入口 ==========
if __name__ == "__main__":
    # 设置s值
    s = 16  # s=32时，迭代轮数=65536，采样数量=16777216
    try:
        parallel_aes_calculation(s)
    except Exception as e:
        print(f"程序执行出错：{e}")