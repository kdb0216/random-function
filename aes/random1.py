import sys
import hashlib
import secrets
import random
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def int_to_bits(n, bit_length):
    """
    将整数转为固定长度的比特列表（高位在前），不足补0
    """
    # 转为二进制字符串，去掉前缀'0b'，不足补0
    bin_str = bin(n)[2:].zfill(bit_length)
    # 转为比特列表（整数0/1）
    return [int(bit) for bit in bin_str]


def bits_to_int(bit_list):
    """
    将比特列表转为整数（高位在前）
    """
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


def aes_round_iteration(s_bits, t_rounds, keys, round_constants):
    """
    t轮AES迭代加密，每轮保留前s比特输入下一轮
    s_bits: 输入/输出比特长度（s≤128，建议为8的倍数）
    t_rounds: 迭代轮数
    keys: 每轮密钥列表 [k1, k2, ..., kt]
    round_constants: 轮常数列表 [c1, c2, ..., ct]
    输出: 字典 {输入值: 最终输出值}
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


def single_input_encrypt(input_val, s_bits, t_rounds, keys, round_constants):
    """对单个输入值执行t轮AES迭代加密，返回输出值"""
    if input_val < 0 or input_val >= 2 ** s_bits:
        raise ValueError(f"输入值必须在0~{2 ** s_bits - 1}范围内（{s_bits}比特）")

    aes_block_bits = 128
    # 1. 将s比特输入值转为128比特列表（不足补0）
    input_bits = int_to_bits(input_val, s_bits)
    current_bits = input_bits + [0] * (aes_block_bits - s_bits)

    # 2. t轮迭代
    for round_idx in range(t_rounds):
        round_key = keys[round_idx]
        round_const = round_constants[round_idx]

        # 2.1 将当前128比特列表转为字节
        current_int = bits_to_int(current_bits)
        current_bytes = current_int.to_bytes(16, byteorder='big')

        # 2.2 轮常数混合（字节级异或）
        current_bytes = bytes([a ^ b for a, b in zip(current_bytes, round_const)])

        # 2.3 单轮AES加密
        cipher_bytes = aes_encrypt_block(current_bytes, round_key)

        # 2.4 将加密后的字节转回128比特列表，截取前s比特作为下一轮输入
        cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
        cipher_bits = int_to_bits(cipher_int, aes_block_bits)
        current_bits = cipher_bits[:s_bits] + [0] * (aes_block_bits - s_bits)

    # 3. 最终输出
    final_output_bits = current_bits[:s_bits]
    final_output_val = bits_to_int(final_output_bits)
    return final_output_val


def random_check_max_output(x, s_bits, t_rounds, keys, round_constants, max_output_val):
    """
    随机选取x个不同的s-bit输入，检查输出是否包含原像最多的输出值
    返回：选中的输入列表、输出列表、是否包含目标输出
    """
    # 生成所有可能的输入值范围
    all_possible_inputs = list(range(2 ** s_bits))
    # 随机选取x个不同的输入
    if x > len(all_possible_inputs):
        raise ValueError(f"x不能超过{s_bits}比特的最大输入数：{len(all_possible_inputs)}")

    selected_inputs = random.sample(all_possible_inputs, x)
    output_results = []

    print(f"\n随机选取的{x}个输入值（{s_bits}比特）：")
    for idx, in_val in enumerate(selected_inputs):
        out_val = single_input_encrypt(in_val, s_bits, t_rounds, keys, round_constants)
        output_results.append(out_val)
        print(
            f"输入 {idx + 1}: 0b{bin(in_val)[2:].zfill(s_bits)} (十进制: {in_val}) -> 输出: 0b{bin(out_val)[2:].zfill(s_bits)} (十进制: {out_val})")

    # 检查是否包含原像最多的输出值
    contains_max_output = max_output_val in output_results
    return selected_inputs, output_results, contains_max_output


if __name__ == "__main__":
    # 配置参数
    s = 12  # 输入/输出比特数
    t = 16  # 迭代轮数

    # 128个16字节AES密钥（k1~k128）
    keys = [
        bytes.fromhex("5f8a9d7b2c4e6f1089abcdef01234567"),  # k1
        bytes.fromhex("a1b2c3d4e5f607089988776655443322"),  # k2
        bytes.fromhex("10293847566574839201aabbccddeeff"),  # k3
        bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f"),  # k4
        bytes.fromhex("4a7d9c8b0e2f1a3c5b7d9f8e6c4a2b0d"),  # k5
        bytes.fromhex("89abcdef012345675f8a9d7b2c4e6f10"),  # k6
        bytes.fromhex("9988776655443322a1b2c3d4e5f60708"),  # k7
        bytes.fromhex("9201aabbccddeeff1029384756657483"),  # k8
        bytes.fromhex("78695a4b3c2d1e0ff0e1d2c3b4a59687"),  # k9
        bytes.fromhex("0e2f1a3c5b7d9f8e4a7d9c8b6c4a2b0d"),  # k10
        bytes.fromhex("6789abcd012345ef123456789abcdef0"),  # k11
        bytes.fromhex("fedcba98765432100123456789abcdef"),  # k12
        bytes.fromhex("112233445566778899aabbccddeeff00"),  # k13
        bytes.fromhex("a0b1c2d3e4f5061728394a5b6c7d8e9f"),  # k14
        bytes.fromhex("b9876543210fedcba9876543210fedcb"),  # k15
        bytes.fromhex("c8d7e6f504132231405968778695a4b3"),  # k16
    ]

    # 128个16字节轮常数（c1~c128）
    round_constants = [
        bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),  # c1
        bytes.fromhex("1112131415161718191a1b1c1d1e1f20"),  # c2
        bytes.fromhex("2122232425262728292a2b2c2d2e2f30"),  # c3
        bytes.fromhex("3132333435363738393a3b3c3d3e3f40"),  # c4
        bytes.fromhex("4142434445464748494a4b4c4d4e4f50"),  # c5
        bytes.fromhex("5152535455565758595a5b5c5d5e5f60"),  # c6
        bytes.fromhex("6162636465666768696a6b6c6d6e6f70"),  # c7
        bytes.fromhex("7172737475767778797a7b7c7d7e7f80"),  # c8
        bytes.fromhex("8182838485868788898a8b8c8d8e8f90"),  # c9
        bytes.fromhex("9192939495969798999a9b9c9d9e9fa0"),  # c10
        bytes.fromhex("a1a2a3a4a5a6a7a8a9aaabacadaeafb0"),  # c11
        bytes.fromhex("b1b2b3b4b5b6b7b8b9babbbcbdbebfc0"),  # c12
        bytes.fromhex("c1c2c3c4c5c6c7c8c9cacbcccdcecfd0"),  # c13
        bytes.fromhex("d1d2d3d4d5d6d7d8d9dadbdcdddedfe0"),  # c14
        bytes.fromhex("e1e2e3e4e5e6e7e8e9eaebecedeeeff0"),  # c15
        bytes.fromhex("f1f2f3f4f5f6f7f8f9fafbfcfdfeff00"),  # c16
    ]

    # 执行t轮AES迭代
    print(f"开始执行 {t} 轮AES迭代，输入/输出比特数：{s}")
    input_output = aes_round_iteration(s, t, keys, round_constants)

    # 分析输出分布
    unique_outputs, max_output, max_count, min_output, min_count, hist = analyze_output_distribution(input_output)

    # 打印基础统计结果
    print(f"\n统计结果（s={s}比特）：")
    print(f"1. 不同的输出数量：{unique_outputs}")
    print(f"2. 原像最多的输出值：0b{bin(max_output)[2:].zfill(s)}（十进制：{max_output}），原像数：{max_count}")
    print(f"3. 原像最少的输出值：0b{bin(min_output)[2:].zfill(s)}（十进制：{min_output}），原像数：{min_count}")

    # 获取用户输入的x值
    while True:
        try:
            x = int(input(f"\n请输入要随机选取的输入数量x（1~{2 ** s}）："))
            if 1 <= x <= 2 ** s:
                break
            else:
                print(f"输入无效！x必须在1~{2 ** s}之间")
        except ValueError:
            print("输入无效！请输入整数")

    # 随机选取x个输入并检查输出
    selected_inputs, output_results, contains_max = random_check_max_output(
        x, s, t, keys, round_constants, max_output
    )

    # 打印最终检查结果
    print(f"\n检查结果：")
    print(f"原像最多的输出值：0b{bin(max_output)[2:].zfill(s)}（十进制：{max_output}）")
    if contains_max:
        print(f"随机选取的{x}个输入的输出中包含该值")
        # 找出哪些输入输出了这个值
        matched_indices = [i for i, val in enumerate(output_results) if val == max_output]
        print(f"对应的输入索引：{[idx + 1 for idx in matched_indices]}")
    else:
        print(f"随机选取的{x}个输入的输出中不包含该值")