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


def aes_round_collision_count(s_bits, t_rounds, keys, round_constants):
    """
    统计t轮AES迭代中每轮发生碰撞的输出值个数
    s_bits: 输入/输出比特长度（s≤128，建议为8的倍数）
    t_rounds: 迭代轮数
    keys: 每轮密钥列表 [k1, k2, ..., kt]
    round_constants: 轮常数列表 [c1, c2, ..., ct]
    输出:
        每轮碰撞统计结果列表 [round_1_collision_num, round_2_collision_num, ..., round_t_collision_num]
        每个元素为对应轮次发生碰撞的输出值个数
    """
    if len(keys) != t_rounds or len(round_constants) != t_rounds:
        raise ValueError("密钥/轮常数数量必须等于迭代轮数t")
    if s_bits < 1 or s_bits > 128:
        raise ValueError("s_bits必须是1~128之间的整数")

    aes_block_bits = 128  # AES块长度
    total_inputs = 2 ** s_bits  # 所有可能的输入数量
    round_collision_nums = []  # 仅存储每轮发生碰撞的输出值个数

    # 初始化每轮的输出计数（仅记录每个输出值被多少个输入映射到）
    round_output_counts = [defaultdict(int) for _ in range(t_rounds)]

    # 遍历所有输入，执行迭代并记录每轮输出
    for input_val in range(total_inputs):
        # 将输入值转为s比特，补齐到128比特
        input_bits = int_to_bits(input_val, s_bits)
        current_bits = input_bits + [0] * (aes_block_bits - s_bits)

        # 逐轮执行AES迭代
        for round_idx in range(t_rounds):
            round_key = keys[round_idx]
            round_const = round_constants[round_idx]

            # 将当前比特转为字节
            current_int = bits_to_int(current_bits)
            current_bytes = current_int.to_bytes(16, byteorder='big')

            # 轮常数混合
            current_bytes = bytes([a ^ b for a, b in zip(current_bytes, round_const)])

            # 单轮AES加密
            cipher_bytes = aes_encrypt_block(current_bytes, round_key)

            # 转回比特列表并截取前s比特作为本轮输出
            cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
            cipher_bits = int_to_bits(cipher_int, aes_block_bits)
            round_output_val = bits_to_int(cipher_bits[:s_bits])

            # 记录本轮输出值的输入个数
            round_output_counts[round_idx][round_output_val] += 1

            # 更新下一轮输入（补齐到128比特）
            current_bits = cipher_bits[:s_bits] + [0] * (aes_block_bits - s_bits)

    # 仅统计每轮发生碰撞的输出值个数（输入个数>1即为碰撞）
    for round_idx in range(t_rounds):
        output_count = round_output_counts[round_idx]
        # 计算发生碰撞的输出值数量
        collision_num = sum(1 for cnt in output_count.values() if cnt > 1)
        round_collision_nums.append(collision_num)

    return round_collision_nums


if __name__ == "__main__":
    # 配置参数
    s = 16  # 输入/输出比特数

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

    # 执行迭代并统计每轮碰撞个数
    print(f"\n开始执行 {t} 轮AES迭代，输入/输出比特数：{s}")
    print(f"已自动生成 {t} 个随机AES密钥和 {t} 个随机轮常数")
    collision_nums = aes_round_collision_count(s, t, keys, round_constants)

    # 打印每轮碰撞统计结果
    print(f"\n===== 每轮碰撞统计结果（s={s}比特） =====")
    for round_idx, collision_num in enumerate(collision_nums):
        print(f"第 {round_idx + 1} 轮：发生碰撞的输出值个数 = {collision_num}")