import sys
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def int_to_bits(n, bit_length):
    return [int(bit) for bit in bin(n)[2:].zfill(bit_length)]


def bits_to_int(bit_list):
    return int(''.join(str(b) for b in bit_list), 2) if bit_list else 0


def aes_encrypt_block(plaintext_bytes, key_bytes):
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext_bytes) + encryptor.finalize()


# 单轮AES映射

def aes_single_round(value, s_bits, key, round_const):
    aes_block_bits = 128

    bits = int_to_bits(value, s_bits)
    bits = bits + [0] * (aes_block_bits - s_bits)

    value_int = bits_to_int(bits)
    value_bytes = value_int.to_bytes(16, byteorder='big')

    # 轮常数异或
    value_bytes = bytes([a ^ b for a, b in zip(value_bytes, round_const)])

    cipher_bytes = aes_encrypt_block(value_bytes, key)

    cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
    cipher_bits = int_to_bits(cipher_int, aes_block_bits)

    return bits_to_int(cipher_bits[:s_bits])


# 带删除机制的多轮迭代

def aes_iterative_with_deletion(s_bits, t_rounds, keys, round_constants):

    # 初始化：每个输入的原像是自己
    current_map = {
        x: {x} for x in range(2 ** s_bits)
    }

    print(f"初始状态：{len(current_map)} 个节点")

    for round_idx in range(t_rounds):

        next_map = defaultdict(set)

        #进行一轮AES
        for value, origin_set in current_map.items():
            new_value = aes_single_round(
                value,
                s_bits,
                keys[round_idx],
                round_constants[round_idx]
            )

            next_map[new_value].update(origin_set)

        print(f"\n第 {round_idx+1} 轮后：")
        print(f"  输出节点数：{len(next_map)}")

        #删除机制
        if round_idx < 10:
            delete_ratio = min(0.03 * (round_idx + 1), 0)

            # 统计原像数
            preimage_list = [
                (output_val, len(origins))
                for output_val, origins in next_map.items()
            ]

            # 按原像数升序排序
            preimage_list.sort(key=lambda x: x[1])

            delete_count = int(len(preimage_list) * delete_ratio)

            delete_outputs = set(
                output for output, _ in preimage_list[:delete_count]
            )

            # 删除
            next_map = {
                output: origins
                for output, origins in next_map.items()
                if output not in delete_outputs
            }

            print(f"  删除比例：{delete_ratio*100:.0f}%")
            print(f"  删除节点数：{delete_count}")
            print(f"  删除后剩余节点数：{len(next_map)}")

        else:
            print("  本轮不删除")

        if next_map:

            max_output = None
            max_count = -1
            min_output = None
            min_count = float('inf')

            for output, origins in next_map.items():
                count = len(origins)

                if count > max_count:
                    max_count = count
                    max_output = output

                if count < min_count:
                    min_count = count
                    min_output = output

            print(f"最大原像数：{max_count}")
            print(f"原像最多的输出值：0b{bin(max_output)[2:].zfill(s_bits)} (十进制 {max_output})")

            print(f"最小原像数：{min_count}")
            print(f"原像最少的输出值：0b{bin(min_output)[2:].zfill(s_bits)} (十进制 {min_output})")

        current_map = next_map

    return current_map



if __name__ == "__main__":

    s = 16
    t = 16

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

    final_map = aes_iterative_with_deletion(
        s,
        t,
        keys,
        round_constants
    )

    print("\n最终剩余节点数：", len(final_map))