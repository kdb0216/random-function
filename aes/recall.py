import sys
import hashlib
import secrets
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
    """AES加密"""
    key_len = len(key_bytes)
    if key_len not in [16, 24, 32]:
        raise ValueError("密钥长度必须为16/24/32字节（对应AES-128/192/256）")

    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return ciphertext


def aes_round_iteration(s_bits, t_rounds, keys, round_constants):
    """
    t轮AES迭代加密，每轮保留前s比特输入下一轮
    返回「每轮输入输出的链式映射」——{上一轮输出: 本轮输出}
    s_bits: 输入/输出比特长度（s≤128，建议为8的倍数）
    t_rounds: 迭代轮数
    keys: 每轮密钥列表 [k1, k2, ..., kt]
    round_constants: 轮常数列表 [c1, c2, ..., ct]
    输出:
        最终输入输出映射 {输入值: 最终输出值}
        每轮初始输入映射列表 [round_1_map, round_2_map, ..., round_t_map]
        每轮链式映射列表 [round_1_chain, round_2_chain, ..., round_t_chain]
        （chain_map: {上一轮输出值: 本轮输出值}）
    """
    if len(keys) != t_rounds or len(round_constants) != t_rounds:
        raise ValueError("密钥/轮常数数量必须等于迭代轮数t")
    if s_bits < 1 or s_bits > 128:
        raise ValueError("s_bits必须是1~128之间的整数")

    aes_block_bits = 128  # AES块长度
    total_inputs = 2 ** s_bits  # 所有可能的输入数量
    final_input_output = {}  # 最终输入->输出
    round_input_output = [{} for _ in range(t_rounds)]  # 每轮初始输入->本轮输出
    round_chain_maps = [{} for _ in range(t_rounds)]  # 每轮链式映射：上一轮输出->本轮输出

    # 遍历所有输入，执行t轮迭代并记录映射
    for input_val in range(total_inputs):
        # 1. 初始化：s比特输入补齐到128比特
        input_bits = int_to_bits(input_val, s_bits)
        prev_round_output = bits_to_int(input_bits)  # 初始输入作为第0轮输出
        current_bits = input_bits + [0] * (aes_block_bits - s_bits)

        # 2. 逐轮迭代
        for round_idx in range(t_rounds):
            round_key = keys[round_idx]
            round_const = round_constants[round_idx]

            # 2.1 比特转字节
            current_int = bits_to_int(current_bits)
            current_bytes = current_int.to_bytes(16, byteorder='big')

            # 2.2 轮常数混合
            current_bytes = bytes([a ^ b for a, b in zip(current_bytes, round_const)])

            # 2.3 单轮AES加密
            cipher_bytes = aes_encrypt_block(current_bytes, round_key)

            # 2.4 字节转回比特，截取前s比特
            cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
            cipher_bits = int_to_bits(cipher_int, aes_block_bits)
            current_bits = cipher_bits[:s_bits] + [0] * (aes_block_bits - s_bits)
            current_round_output = bits_to_int(current_bits[:s_bits])

            # 2.5 记录：初始输入->本轮输出
            round_input_output[round_idx][input_val] = current_round_output
            # 2.6 记录：上一轮输出->本轮输出（链式映射）
            if prev_round_output not in round_chain_maps[round_idx]:
                round_chain_maps[round_idx][prev_round_output] = current_round_output
            # 2.7 更新上一轮输出为当前输出
            prev_round_output = current_round_output

        # 3. 记录最终输出
        final_input_output[input_val] = prev_round_output

    return final_input_output, round_input_output, round_chain_maps


def analyze_output_distribution(input_output_map):
    """分析输出分布：统计不同输出数、原像最多/最少的输出及数量"""
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


def track_max_output_tree_layers(max_target, initial_inputs, round_chain_maps, t_rounds):
    """
    逻辑：
    - 第1层：初始原像集合
    - 第2层：第1轮迭代后，原像集合的输出值
    - ...
    - 最后一层：目标值
    max_target: 目标输出值
    initial_inputs: 能生成目标值的所有初始输入
    round_chain_maps: 每轮链式映射列表（上一轮输出->本轮输出）
    t_rounds: 迭代轮数
    返回：每一层节点数列表
    """
    # 第1层：原始原像数
    current_nodes = set(initial_inputs)
    layer_counts = [len(current_nodes)]

    # 逐轮追踪：上一轮输出 → 本轮输出
    for round_idx in range(t_rounds):
        chain_map = round_chain_maps[round_idx]
        next_nodes = set()
        for node in current_nodes:
            next_nodes.add(chain_map[node])
        layer_counts.append(len(next_nodes))
        current_nodes = next_nodes

    return layer_counts


if __name__ == "__main__":
    # 配置参数
    s = 12  # 输入/输出比特数

    # 获取输入的迭代轮数t
    while True:
        try:
            t_input = input("请输入迭代轮数t（正整数）：")
            t = int(t_input)
            if t <= 0:
                print("迭代轮数必须为正整数，请重新输入！")
                continue
            break
        except ValueError:
            print("输入无效，请输入有效的正整数！")

    # 自动生成t个16字节AES密钥和轮常数
    keys = [secrets.token_bytes(16) for _ in range(t)]
    round_constants = [secrets.token_bytes(16) for _ in range(t)]

    # 执行t轮AES迭代
    print(f"\n开始执行 {t} 轮AES迭代，输入/输出比特数：{s}")
    final_io_map, round_io_maps, round_chain_maps = aes_round_iteration(s, t, keys, round_constants)

    # 分析最终输出分布
    unique_outputs, max_output, max_count, min_output, min_count, hist = analyze_output_distribution(final_io_map)

    # 打印基础结果
    print(f"\n===== 最终迭代结果（t={t}轮） =====")
    print(f"1. 总输入数量：{2 ** s}")
    print(f"2. 不同的输出数量：{unique_outputs}")
    print(f"3. 原像最多的输出值：0b{bin(max_output)[2:].zfill(s)}（十进制：{max_output}），原像数：{max_count}")
    print(f"4. 原像最少的输出值：0b{bin(min_output)[2:].zfill(s)}（十进制：{min_output}），原像数：{min_count}")

    # 找到能生成目标值的所有初始输入
    initial_inputs = [inp for inp, out in final_io_map.items() if out == max_output]

    # 追踪树状层级节点数
    print(f"\n===== 目标输出值（{max_output}）的树状层级节点数 =====")
    layer_counts = track_max_output_tree_layers(max_output, initial_inputs, round_chain_maps, t)

    # 打印每一层节点数
    print("层级 -> 节点数：")
    for idx, count in enumerate(layer_counts):
        if idx == 0:
            print(f"第 1 层（原像）-> 节点数：{count} ")
        elif 0 < idx < t:
            print(f"第 {idx + 1} 层（第{idx}轮后）-> 节点数：{count} ")
        elif idx == t:
            print(f"第 {idx + 1} 层（最终输出）-> 节点数：{count} ")

    # 每轮基础统计
    print(f"\n===== 每轮迭代基础统计 =====")
    for round_idx in range(t):
        round_map = round_io_maps[round_idx]
        unique = len(set(round_map.values()))
        output_count = defaultdict(int)
        for v in round_map.values():
            output_count[v] += 1
        max_r_count = max(output_count.values()) if output_count else 0
        min_r_count = min(output_count.values()) if output_count else 0
        print(f"第 {round_idx + 1} 轮：")
        print(f"  - 不同输出数：{unique}")
        print(f"  - 输出最多原像数：{max_r_count}")
        print(f"  - 输出最少原像数：{min_r_count}")