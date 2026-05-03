import sys
import hashlib
import random
import math
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from multiprocessing import Pool, cpu_count
import time
import os

# 设置随机种子（可选，用于复现）
random.seed(42)


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
    # 复用backend减少初始化开销
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=backend)
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


# ========== 分批处理辅助函数 ==========
def process_batch(batch_args, num_processes):
    """
    处理单批次任务
    :param batch_args: 单批次任务参数列表
    :param num_processes: 进程数
    :return: 该批次处理结果
    """
    with Pool(processes=num_processes) as pool:
        batch_results = pool.map(process_single_input, batch_args)
    return batch_results


# ========== 并行执行主函数（适配192 vCPUs） ==========
def parallel_aes_calculation(s, num_processes=192, batch_size=None):
    """
    并行执行AES迭代计算，适配192 vCPUs
    :param s: 输入/输出比特长度
    :param num_processes: 进程数（默认192）
    :param batch_size: 每批次处理数量（默认按进程数*100）
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

    # 3. 生成采样输入列表（优化生成效率）
    print("生成采样输入列表...")
    max_input_val = max_possible_sample - 1
    # 优化：当采样量极大时，改用生成器+分块采样
    if sample_size > 10_000_000:
        sampled_inputs = []
        chunk_size = 1_000_000
        remaining = sample_size
        while remaining > 0:
            take = min(chunk_size, remaining)
            chunk = random.sample(range(max_input_val + 1), take)
            sampled_inputs.extend(chunk)
            remaining -= take
            print(f"已生成 {sample_size - remaining}/{sample_size} 个采样输入")
    else:
        sampled_inputs = random.sample(range(max_input_val + 1), sample_size)

    # 4. 配置分批处理（避免192进程同时加载所有任务导致内存溢出）
    if batch_size is None:
        batch_size = num_processes * 100  # 每批次进程数*100个任务
    num_batches = math.ceil(len(sampled_inputs) / batch_size)
    print(f"配置分批处理：共{num_batches}批次，每批次{batch_size}个任务")
    print(f"启动 {num_processes} 个进程（适配192 vCPUs）...")

    start_time = time.time()

    # 5. 分批执行并行处理
    input_output_map = {}
    for batch_idx in range(num_batches):
        # 切分批次
        start_idx = batch_idx * batch_size
        end_idx = min((batch_idx + 1) * batch_size, len(sampled_inputs))
        batch_inputs = sampled_inputs[start_idx:end_idx]

        # 构造批次任务参数
        batch_task_args = [(val, s, t_rounds, keys, round_constants) for val in batch_inputs]

        # 处理当前批次
        print(f"处理批次 {batch_idx + 1}/{num_batches}（{len(batch_task_args)}个任务）...")
        batch_start = time.time()
        batch_results = process_batch(batch_task_args, num_processes)
        batch_end = time.time()

        # 整理批次结果
        for input_val, output_val in batch_results:
            if output_val is not None:
                input_output_map[input_val] = output_val

        print(f"批次 {batch_idx + 1} 耗时：{batch_end - batch_start:.2f} 秒")
        print(f"累计处理：{len(input_output_map)}/{sample_size} 个有效输入")

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
    print(f"进程数配置 = {num_processes}（适配192 vCPUs）")

    return unique_output_count


# ========== 执行入口 ==========
if __name__ == "__main__":
    # 设置s值（可根据需要调整）
    s = 16  # s=32时，迭代轮数=65536，采样数量=16777216
    try:
        # 适配192 vCPUs：进程数设为192，可根据实际情况微调（如180/200）
        # 批次大小可根据内存调整，默认192*100=19200
        parallel_aes_calculation(
            s=s,
            num_processes=192,
            batch_size=19200  # 每批次处理19200个任务，避免内存占用过高
        )
    except Exception as e:
        print(f"程序执行出错：{e}")
        sys.exit(1)