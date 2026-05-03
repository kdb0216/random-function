import sys
import hashlib
import secrets
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def int_to_bits(n, bit_length):
    """
    将整数转为固定长度的比特列表，不足补0
    """
    bin_str = bin(n)[2:].zfill(bit_length)
    return [int(bit) for bit in bin_str]


def bits_to_int(bit_list):
    """
    将比特列表转为整数
    """
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
    新增：每轮迭代后统计并返回各轮的输出分布（不同输出个数）
    s_bits: 输入/输出比特长度（s≤128，建议为8的倍数）
    t_rounds: 迭代轮数
    keys: 每轮密钥列表 [k1, k2, ..., kt]
    round_constants: 轮常数列表 [c1, c2, ..., ct]
    输出: 
        最终输入输出映射 {输入值: 最终输出值}
        每轮统计结果列表 [round_1_stats, round_2_stats, ..., round_t_stats]
        其中每个stats为字典：{'unique_outputs': 不同输出数, 'output_count': 输出值-原像数映射}
    """
    if len(keys) != t_rounds or len(round_constants) != t_rounds:
        raise ValueError("密钥/轮常数数量必须等于迭代轮数t")
    if s_bits < 1 or s_bits > 128:
        raise ValueError("s_bits必须是1~128之间的整数")

    aes_block_bits = 128  # AES块长度
    total_inputs = 2 ** s_bits  # 所有可能的输入数量
    input_output_map = {}
    round_stats_list = []  # 存储每轮的统计结果

    for input_val in range(total_inputs):
        # 1. 将s比特输入值转为128比特列表（不足补0）
        input_bits = int_to_bits(input_val, s_bits)  # s比特输入
        current_bits = input_bits + [0] * (aes_block_bits - s_bits)  # 补齐到128比特

        # 2. t轮迭代（每轮记录当前输出）
        for round_idx in range(t_rounds):
            round_key = keys[round_idx]
            round_const = round_constants[round_idx]

            # 2.1 将当前128比特列表转为字节
            current_int = bits_to_int(current_bits)
            current_bytes = current_int.to_bytes(16, byteorder='big')  # 16字节=128比特

            # 2.2 轮常数混合
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

    # 重新执行迭代，记录每轮的输出
    # 重新遍历所有输入，逐轮记录输出
    round_outputs = [{} for _ in range(t_rounds)]  # 每轮的{输入值: 本轮输出值}
    for input_val in range(total_inputs):
        input_bits = int_to_bits(input_val, s_bits)
        current_bits = input_bits + [0] * (aes_block_bits - s_bits)

        for round_idx in range(t_rounds):
            round_key = keys[round_idx]
            round_const = round_constants[round_idx]

            # 执行本轮AES加密
            current_int = bits_to_int(current_bits)
            current_bytes = current_int.to_bytes(16, byteorder='big')
            current_bytes = bytes([a ^ b for a, b in zip(current_bytes, round_const)])
            cipher_bytes = aes_encrypt_block(current_bytes, round_key)
            cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
            cipher_bits = int_to_bits(cipher_int, aes_block_bits)
            current_bits = cipher_bits[:s_bits] + [0] * (aes_block_bits - s_bits)

            # 记录本轮输出（前s比特转为整数）
            round_output_val = bits_to_int(current_bits[:s_bits])
            round_outputs[round_idx][input_val] = round_output_val

    # 统计每轮的输出分布
    for round_idx in range(t_rounds):
        output_count = defaultdict(int)
        for output_val in round_outputs[round_idx].values():
            output_count[output_val] += 1
        unique_outputs = len(output_count)
        round_stats_list.append({
            'round': round_idx + 1,  # 轮数从1开始
            'unique_outputs': unique_outputs,
            'output_count': dict(output_count),  # 输出值: 原像数
            'input_output': round_outputs[round_idx]  # 输入值: 本轮输出值（可选）
        })

    return input_output_map, round_stats_list


def analyze_output_distribution(input_output_map):
    """分析输出分布：统计不同输出数、原像最多的输出及数量"""
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

    # 自动生成t个16字节AES密钥（k1~kt）
    keys = []
    for i in range(t):
        key_bytes = secrets.token_bytes(16)
        keys.append(key_bytes)

    # 自动生成t个16字节轮常数（c1~ct）
    round_constants = []
    for i in range(t):
        const_bytes = secrets.token_bytes(16)
        round_constants.append(const_bytes)

    # 执行t轮AES迭代（获取最终结果+每轮统计）
    print(f"\n开始执行 {t} 轮AES迭代，输入/输出比特数：{s}")
    print(f"已自动生成 {t} 个随机AES密钥和 {t} 个随机轮常数")
    input_output, round_stats = aes_round_iteration(s, t, keys, round_constants)

    # 打印每轮的统计结果
    sum_unique_counts = [2 ** s]
    print(f"\n===== 每轮迭代后统计结果（s={s}比特） =====")
    for stats in round_stats:
        round_num = stats['round']
        unique_outputs = stats['unique_outputs']
        # 分析本轮的最大/最小原像数
        output_count = stats['output_count']
        max_count = max(output_count.values()) if output_count else 0
        min_count = min(output_count.values()) if output_count else 0
        print(f"\n第 {round_num} 轮：")
        print(f"  - 不同输出的个数：{unique_outputs}")
        print(f"  - 原像最多的输出数：{max_count}")
        print(f"  - 原像最少的输出数：{min_count}")

        if round_num < t:
            sum_unique_counts.append(unique_outputs)

    # 分析最终输出分布
    unique_outputs, max_output, max_count, min_output, min_count, hist = analyze_output_distribution(input_output)

    # 打印最终结果
    total_sum = sum(sum_unique_counts)
    print(f"\n===== 最终迭代结果（t={t}轮） =====")
    print(f"1. 计算复杂度：{total_sum}")
    print(f"2. 不同的输出数量：{unique_outputs}")
    print(f"3. 原像最多的输出值：0b{bin(max_output)[2:].zfill(s)}（十进制：{max_output}），原像数：{max_count}")
    print(f"4. 原像最少的输出值：0b{bin(min_output)[2:].zfill(s)}（十进制：{min_output}），原像数：{min_count}")