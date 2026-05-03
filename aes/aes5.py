import random
import secrets
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import matplotlib.pyplot as plt
import matplotlib as mpl


# 设置matplotlib支持中文显示
def setup_chinese_font():
    """配置matplotlib以支持中文显示"""
    # 设置字体（优先使用系统中的中文字体）
    try:
        # Windows系统
        plt.rcParams['font.sans-serif'] = ['Microsoft YaHei', 'SimHei', 'DejaVu Sans']
    except:
        # Linux/Mac系统
        plt.rcParams['font.sans-serif'] = ['WenQuanYi Micro Hei', 'Heiti TC', 'DejaVu Sans']

    # 解决负号显示问题
    plt.rcParams['axes.unicode_minus'] = False

    # 禁用字体缓存警告
    mpl.rcParams['font.family'] = 'sans-serif'


def int_to_bits(n, bit_length):
    bin_str = bin(n)[2:].zfill(bit_length)
    return [int(b) for b in bin_str]


def bits_to_int(bit_list):
    return int("".join(str(b) for b in bit_list), 2)


def aes_encrypt_block(plaintext_bytes, key_bytes):
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext_bytes) + encryptor.finalize()


def F_once(m_val, s_bits, key, const):
    aes_block_bits = 128

    bits = int_to_bits(m_val, s_bits) + [0] * (aes_block_bits - s_bits)
    x_int = bits_to_int(bits)
    x_bytes = x_int.to_bytes(16, "big")

    x_bytes = bytes(a ^ b for a, b in zip(x_bytes, const))
    cipher = aes_encrypt_block(x_bytes, key)

    y = int.from_bytes(cipher, "big")
    y_bits = int_to_bits(y, aes_block_bits)

    return bits_to_int(y_bits[:s_bits])


def iterate_F(x, k, s_bits, keys, consts):
    v = x
    for i in range(k):
        v = F_once(v, s_bits, keys[i], consts[i])
    return v


# 随机输入得到m1..mt
def random_trajectory(s, t, keys, consts):
    m = random.randrange(2 ** s)

    seq = []
    v = m

    for i in range(t):
        v = F_once(v, s, keys[i], consts[i])
        seq.append(v)

    return m, seq


# 原像统计
def preimage_statistics(seq, s, x, keys, consts):
    total = 2 ** s
    results = {}

    for i in range(x - 1, len(seq)):

        target = seq[i]
        count = 0

        for u in range(total):

            v = u

            # 使用第 i-x+1 到 i 轮
            for r in range(i - x + 1, i + 1):
                v = F_once(v, s, keys[r], consts[r])

            if v == target:
                count += 1

        results[i + 1] = count

        print(f"m{i + 1} 的前{x}轮原像数: {count}")

    return results


def draw_histogram(results, x, t):
    xs = []
    ys = []

    for i in range(x, t + 1):
        xs.append(i)
        ys.append(results[i])

    plt.figure(figsize=(10, 5))

    plt.bar(xs, ys)

    plt.xlabel("i (from x to t)")
    plt.ylabel("Preimage count")
    plt.title("Preimage count of mi with x-round backward")

    plt.xticks(xs)

    plt.show()


def draw_ratio_bar_chart(ratios, rounds):
    """
    绘制50次实验比例的柱状图
    横轴：1~50次实验序号
    纵轴：每次实验的比例值
    """
    # 设置中文字体
    setup_chinese_font()

    plt.figure(figsize=(14, 7))

    # 准备x轴数据（1~50）
    experiment_nums = list(range(1, rounds + 1))

    # 绘制柱状图
    bars = plt.bar(experiment_nums, ratios, width=0.7, edgecolor='black', alpha=0.8, color='#2E86AB')

    # 添加平均值水平线
    avg_ratio = sum(ratios) / rounds
    plt.axhline(y=avg_ratio, color='red', linestyle='--', linewidth=2, label=f'Average: {avg_ratio:.4f}')

    # 设置坐标轴标签和标题（使用英文避免字体问题）
    plt.xlabel("Experiment Number (1~50)", fontsize=12)
    plt.ylabel("Ratio Value (larger / total)", fontsize=12)
    plt.title(f"Ratio Value Distribution of 50 Experiments", fontsize=14, pad=20)

    # 设置x轴刻度
    plt.xticks(experiment_nums, rotation=45)

    # 添加网格线（纵向）
    plt.grid(axis='y', alpha=0.3, linestyle='-')

    # 添加图例
    plt.legend(loc='upper right')

    # 添加统计信息文本框（使用英文）
    stats_text = f'Statistics:\nAverage: {avg_ratio:.4f}\nMin: {min(ratios):.4f}\nMax: {max(ratios):.4f}\nStd: {calculate_std(ratios, avg_ratio):.4f}'
    plt.text(0.02, 0.98, stats_text, transform=plt.gca().transAxes,
             verticalalignment='top', bbox=dict(boxstyle='round,pad=0.5', facecolor='wheat', alpha=0.8),
             fontsize=10)

    # 在每个柱子上方显示具体数值
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2., height + 0.005,
                 f'{height:.4f}', ha='center', va='bottom', fontsize=8)

    # 调整布局，防止标签重叠
    plt.tight_layout()

    # 显示图表
    plt.show()


def calculate_std(values, mean):
    """计算标准差"""
    squared_diff = [(v - mean) ** 2 for v in values]
    variance = sum(squared_diff) / len(values)
    return variance ** 0.5


if __name__ == "__main__":

    s = 12
    t = 256
    x = 16

    rounds = 5

    keys = [secrets.token_bytes(16) for _ in range(t)]
    consts = [secrets.token_bytes(16) for _ in range(t)]

    ratios = []

    for exp in range(rounds):

        print(f"\n========== 实验 {exp + 1} ==========\n")

        m0, seq = random_trajectory(s, t, keys, consts)

        result = preimage_statistics(seq, s, x, keys, consts)

        total = 0
        larger = 0

        for i in range(x, t + 1):

            total += 1

            if result[i] > x:
                larger += 1

        ratio = larger / total

        ratios.append(ratio)

        print(f"本次比例: {ratio}")

    avg_ratio = sum(ratios) / rounds

    print("\n=============================")
    print("平均比例:", avg_ratio)

    draw_ratio_bar_chart(ratios, rounds)
