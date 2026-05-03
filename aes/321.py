import sys
import hashlib
import secrets
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

    return unique_outputs, max_output, max_count, min_output, min_count, count_histogram, output_count


def filter_high_preimage_outputs(output_count, threshold):
    """筛选原像数≥阈值的输出值，返回{输出值: 原像数}"""
    high_preimage_outputs = {}
    for output_val, count in output_count.items():
        if count >= threshold:
            high_preimage_outputs[output_val] = count
    # 按原像数降序排序
    sorted_high_outputs = dict(sorted(high_preimage_outputs.items(), key=lambda x: x[1], reverse=True))
    return sorted_high_outputs


if __name__ == "__main__":
    # 配置参数
    s = 12  # 输入/输出比特数
    t = 16  # 迭代轮数

    # 128个16字节AES密钥（k1~k128）
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

    # 执行t轮AES迭代
    print(f"开始执行 {t} 轮AES迭代，输入/输出比特数：{s}")
    input_output = aes_round_iteration(s, t, keys, round_constants)

    # 分析输出分布（新增返回output_count）
    unique_outputs, max_output, max_count, min_output, min_count, hist, output_count = analyze_output_distribution(input_output)

    # 筛选原像数≥t的输出值
    threshold = t
    high_preimage_outputs = filter_high_preimage_outputs(output_count, threshold)

    # 打印原有统计结果
    print(f"\n===== 基础统计结果（s={s}比特，t={t}轮） =====")
    print(f"1. 不同的输出数量：{unique_outputs}")
    print(f"2. 原像最多的输出值：0b{bin(max_output)[2:].zfill(s)}（十进制：{max_output}），原像数：{max_count}")
    print(f"3. 原像最少的输出值：0b{bin(min_output)[2:].zfill(s)}（十进制：{min_output}），原像数：{min_count}")

    # 打印原像数≥t的输出值
    print(f"\n===== 原像数≥{t}的输出值（共{len(high_preimage_outputs)}个） =====")
    if high_preimage_outputs:
        for idx, (output_val, count) in enumerate(high_preimage_outputs.items(), 1):
            bin_str = bin(output_val)[2:].zfill(s)
            print(f"{idx}. 输出值：0b{bin_str}（十进制：{output_val}），原像数：{count}")
    else:
        print(f"无原像数≥{t}的输出值")