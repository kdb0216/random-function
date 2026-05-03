import sys
import hashlib
import secrets
import random
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
    """AES加密（完整流程）"""
    key_len = len(key_bytes)
    if key_len not in [16, 24, 32]:
        raise ValueError("密钥长度必须为16/24/32字节（对应AES-128/192/256）")

    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return ciphertext


def aes_round_iteration_filtered(s_bits, t_rounds, keys, round_constants, start_filter_round, end_filter_round):
    """
    带碰撞过滤的t轮AES迭代加密（原函数补全end_filter_round参数）
    :param s_bits: 输入/输出比特长度（s≤128，建议为8的倍数）
    :param t_rounds: 总迭代轮数
    :param keys: 每轮密钥列表 [k1, k2, ..., kt]
    :param round_constants: 轮常数列表 [c1, c2, ..., ct]
    :param start_filter_round: 从第几轮开始过滤未碰撞输入（1-based）
    :param end_filter_round: 过滤结束轮数（1-based）
    :return: 最终输入输出映射、每轮保留的输入数统计
    """
    if len(keys) != t_rounds or len(round_constants) != t_rounds:
        raise ValueError("密钥/轮常数数量必须等于迭代轮数t")
    if s_bits < 1 or s_bits > 128:
        raise ValueError("s_bits必须是1~128之间的整数")

    aes_block_bits = 128  # AES块长度
    random_sample_count = 2 ** 12
    # 初始输入集合：所有可能的s比特值中随机选取
    max_input_val = 2 ** s_bits - 1
    current_inputs = set(random.sample(range(max_input_val + 1), random_sample_count))
    # 验证选取数量（防止边界情况）
    assert len(current_inputs) == random_sample_count, "随机选取的输入数量不符合要求"
    # 记录每轮保留的输入数
    round_keep_count = []
    # 存储每轮输入->输出的映射（用于过滤）
    round_input_output = {}
    input_to_latest_output = {inp: inp for inp in current_inputs}  # 初始输出=输入

    for round_idx in range(t_rounds):
        round_num = round_idx + 1  # 1-based轮数
        round_key = keys[round_idx]
        round_const = round_constants[round_idx]

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

        input_to_latest_output = current_io_map
        # 保存本轮输入输出映射
        round_input_output[round_num] = current_io_map
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
                    keep_inputs.add(out_val)  # 保留碰撞的输入值
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

    return current_io_map, round_keep_count


def single_input_full_iteration(input_val, s_bits, t_rounds, keys, round_constants):
    """
    单个输入值执行完整t轮AES迭代（无过滤）
    :param input_val: 输入的s比特整数值
    :param s_bits: 输入/输出比特长度
    :param t_rounds: 总迭代轮数
    :param keys: 每轮密钥列表
    :param round_constants: 每轮常数列表
    :return: 最终输出值
    """
    aes_block_bits = 128
    current_val = input_val

    for round_idx in range(t_rounds):
        round_key = keys[round_idx]
        round_const = round_constants[round_idx]

        # 1. 转为128比特列表
        input_bits = int_to_bits(current_val, s_bits)
        current_bits = input_bits + [0] * (aes_block_bits - s_bits)

        # 2. 转为字节
        current_int = bits_to_int(current_bits)
        current_bytes = current_int.to_bytes(16, byteorder='big')

        # 3. 轮常数混合（字节级异或）
        current_bytes = bytes([a ^ b for a, b in zip(current_bytes, round_const)])

        # 4. 单轮AES加密
        cipher_bytes = aes_encrypt_block(current_bytes, round_key)

        # 5. 转回比特列表，截取前s比特作为本轮输出
        cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
        cipher_bits = int_to_bits(cipher_int, aes_block_bits)
        output_bits = cipher_bits[:s_bits]
        current_val = bits_to_int(output_bits)

    return current_val


def test_probability(s, t, test_times, start_filter_round=1, end_filter_round=1):
    """
    循环测试多次，统计随机输入的最终输出在过滤后列表中的概率
    :param s: 比特长度
    :param t: 迭代轮数
    :param test_times: 测试次数
    :param start_filter_round: 过滤起始轮数
    :param end_filter_round: 过滤结束轮数
    :return: 成功次数、失败次数、成功率
    """
    # 1. 生成固定的密钥和轮常数（确保所有测试使用相同的迭代参数）
    random.seed(12345)  # 固定种子保证可复现
    secrets.SystemRandom().seed(12345)
    keys = [secrets.token_bytes(16) for _ in range(t)]
    round_constants = [secrets.token_bytes(16) for _ in range(t)]

    # 2. 先执行一次过滤流程，获取固定的过滤后输出列表
    print("===== 执行初始过滤流程，生成基准输出列表 =====")
    final_io_map, round_keep_counts = aes_round_iteration_filtered(
        s, t, keys, round_constants, start_filter_round, end_filter_round
    )
    filtered_outputs = list(final_io_map.values())
    print(f"过滤后的输出列表长度：{len(filtered_outputs)}")
    if len(filtered_outputs) == 0:
        print("⚠️ 警告：过滤后的输出列表为空，所有测试都会失败")

    # 3. 循环执行多次测试
    success_count = 0  # 成功次数（输出在列表中）
    fail_count = 0  # 失败次数（输出不在列表中）
    max_s_val = 2 ** s - 1

    print(f"\n===== 开始执行 {test_times} 次测试 =====")
    for test_idx in range(test_times):
        # 生成随机s比特输入
        random_input = random.randint(0, max_s_val)
        # 执行完整迭代
        final_output = single_input_full_iteration(random_input, s, t, keys, round_constants)
        # 检查结果
        if final_output in filtered_outputs:
            success_count += 1
            result = "成功"
        else:
            fail_count += 1
            result = "失败"

        # 每10次打印一次进度（避免输出过多）
        if (test_idx + 1) % 10 == 0 or test_idx == 0 or test_idx == test_times - 1:
            print(f"测试 {test_idx + 1}/{test_times}：输入={random_input}, 输出={final_output}, 结果={result}")

    # 4. 计算概率
    total = success_count + fail_count
    success_rate = (success_count / total) * 100 if total > 0 else 0.0

    # 5. 输出统计结果
    print("\n===== 测试结果统计 =====")
    print(f"总测试次数：{total}")
    print(f"成功次数（输出在列表中）：{success_count}")
    print(f"失败次数（输出不在列表中）：{fail_count}")
    print(f"成功率（概率）：{success_rate:.2f}%")

    return success_count, fail_count, success_rate


if __name__ == "__main__":
    # 配置参数
    s = 16  # 比特长度
    t = 256  # 迭代轮数（建议先小轮数测试，256轮会很慢）
    test_times = 50  # 测试次数（可根据需要调整，如1000次）
    start_filter_round = 1
    end_filter_round = 1

    # 执行概率测试
    success, fail, rate = test_probability(s, t, test_times, start_filter_round, end_filter_round)