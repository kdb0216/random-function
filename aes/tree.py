import sys
import hashlib
import secrets
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# ========== 新增：设置Matplotlib中文支持 ==========
plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']  # 优先使用系统中文宋体
plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题
plt.rcParams['font.family'] = 'sans-serif'


# ========== 原有工具函数（保留） ==========
def int_to_bits(n, bit_length):
    bin_str = bin(n)[2:].zfill(bit_length)
    return [int(bit) for bit in bin_str]


def bits_to_int(bit_list):
    bin_str = ''.join(str(bit) for bit in bit_list)
    return int(bin_str, 2) if bin_str else 0


def aes_encrypt_block(plaintext_bytes, key_bytes):
    key_len = len(key_bytes)
    if key_len not in [16, 24, 32]:
        raise ValueError("密钥长度必须为16/24/32字节（对应AES-128/192/256）")
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return ciphertext


# ========== 新增：记录每轮中间结果的迭代函数 ==========
def aes_round_iteration_with_layers(s_bits, t_rounds, keys, round_constants):
    """
    执行t轮AES迭代，返回每一层的节点和边
    返回：
        layers: 字典 {层号: 节点集合}，层0=初始输入，层1=第一轮输出，...，层t=第t轮输出
        edges: 列表 [(父节点, 子节点, 层号)]，层号表示父节点所在层
        layer_maps: 字典 {层号: {输入值: 输出值}}，记录每一层的输入→输出映射
    """
    if len(keys) != t_rounds or len(round_constants) != t_rounds:
        raise ValueError("密钥/轮常数数量必须等于迭代轮数t")
    if s_bits < 1 or s_bits > 128:
        raise ValueError("s_bits必须是1~128之间的整数")

    aes_block_bits = 128
    total_inputs = 2 ** s_bits
    layers = {0: set(range(total_inputs))}  # 层0：初始输入
    edges = []
    layer_maps = {}

    # 初始输入（层0）
    current_inputs = list(range(total_inputs))

    for round_idx in range(t_rounds):
        round_key = keys[round_idx]
        round_const = round_constants[round_idx]
        current_map = {}  # 本轮输入→输出映射

        for input_val in current_inputs:
            # 1. 转为128比特并补齐
            input_bits = int_to_bits(input_val, s_bits)
            current_bits = input_bits + [0] * (aes_block_bits - s_bits)

            # 2. 字节转换 + 轮常数异或
            current_int = bits_to_int(current_bits)
            current_bytes = current_int.to_bytes(16, byteorder='big')
            current_bytes = bytes([a ^ b for a, b in zip(current_bytes, round_const)])

            # 3. AES加密
            cipher_bytes = aes_encrypt_block(current_bytes, round_key)

            # 4. 转回比特并截取前s比特作为输出
            cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
            cipher_bits = int_to_bits(cipher_int, aes_block_bits)
            output_val = bits_to_int(cipher_bits[:s_bits])

            current_map[input_val] = output_val
            edges.append((input_val, output_val, round_idx))  # 记录边（父节点，子节点，父层）

        # 更新层和映射
        layer_maps[round_idx] = current_map
        current_layer = round_idx + 1
        layers[current_layer] = set(current_map.values())
        current_inputs = list(current_map.values())

    return layers, edges, layer_maps


# ========== 可视化函数（修复中文显示） ==========
def plot_aes_tree(layers, edges, s_bits, t_rounds):
    """
    绘制分层树状图：
    - x轴：层号（0~t）
    - y轴：节点值（归一化）
    - 边：父节点→子节点
    - 颜色：碰撞节点（被多个父节点指向）标红
    """
    # 1. 统计每个节点的入度（碰撞数）
    in_degree = defaultdict(int)
    for parent, child, _ in edges:
        in_degree[child] += 1

    # 2. 创建有向图
    G = nx.DiGraph()
    # 添加所有节点
    for layer, nodes in layers.items():
        G.add_nodes_from(nodes, layer=layer)
    # 添加所有边
    for parent, child, _ in edges:
        G.add_edge(parent, child)

    # 3. 布局：分层布局（每层水平排列）
    pos = {}
    max_node_val = 2 ** s_bits - 1  # 节点最大值
    for layer, nodes in layers.items():
        # 节点按值排序，均匀分布在y轴
        sorted_nodes = sorted(list(nodes))
        y_step = 1.0 / (len(sorted_nodes) + 1) if sorted_nodes else 1.0
        for idx, node in enumerate(sorted_nodes):
            pos[node] = (layer, idx * y_step)  # x=层号，y=归一化位置

    # 4. 绘图配置
    plt.figure(figsize=(1.5 * t_rounds, 8))
    ax = plt.gca()

    # 5. 绘制边（父→子）
    edge_colors = []
    for parent, child, _ in edges:
        # 碰撞边标红，否则灰色
        edge_colors.append('red' if in_degree[child] > 1 else 'lightgray')
    nx.draw_networkx_edges(G, pos, edgelist=[(p, c) for p, c, _ in edges],
                           edge_color=edge_colors, alpha=0.6, arrows=True, ax=ax)

    # 6. 绘制节点：碰撞节点标红，否则蓝色
    node_colors = []
    node_sizes = []
    for node in G.nodes():
        if in_degree[node] > 1:
            node_colors.append('red')
            node_sizes.append(200)  # 碰撞节点放大
        else:
            node_colors.append('steelblue')
            node_sizes.append(100)
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, ax=ax)

    # 7. 标注（仅标注碰撞节点，避免重叠）
    collision_nodes = [n for n in G.nodes() if in_degree[n] > 1]
    nx.draw_networkx_labels(G, pos, labels={n: f"{n}" for n in collision_nodes},
                            font_size=8, font_color='white', ax=ax)

    # 8. 样式配置（中文标签）
    ax.set_xlim(-0.5, t_rounds + 0.5)
    ax.set_ylim(-0.1, 1.1)
    ax.set_xlabel("迭代轮数（层0=初始输入）", fontsize=12)
    ax.set_ylabel("节点值（归一化）", fontsize=12)
    ax.set_title(f"AES迭代碰撞树（s={s_bits}比特，t={t_rounds}轮）", fontsize=14)

    # 图例（中文）
    red_patch = mpatches.Patch(color='red', label='碰撞节点/边（入度>1）')
    blue_patch = mpatches.Patch(color='steelblue', label='普通节点（入度=1）')
    gray_patch = mpatches.Patch(color='lightgray', label='普通边（入度=1）')
    plt.legend(handles=[red_patch, blue_patch, gray_patch], loc='upper right')

    plt.tight_layout()
    plt.show()


# ========== 主函数（测试） ==========
if __name__ == "__main__":
    # 配置参数（建议先小值测试，比如s=3，t=3，避免2^11=2048个节点导致绘图卡顿）
    s = 3  # 输入/输出比特数（建议≤5，否则节点过多）
    t = 3  # 迭代轮数（建议≤5）

    # 生成测试用密钥和轮常数（简化版，避免过长）
    keys = [secrets.token_bytes(16) for _ in range(t)]
    round_constants = [secrets.token_bytes(16) for _ in range(t)]

    # 1. 执行迭代并记录分层结果
    print(f"执行{s}比特/{t}轮AES迭代，记录分层结果...")
    layers, edges, layer_maps = aes_round_iteration_with_layers(s, t, keys, round_constants)

    # 2. 打印分层统计
    print("\n各层节点统计：")
    for layer in sorted(layers.keys()):
        node_count = len(layers[layer])
        print(f"层{layer}：{node_count}个节点")

    # 3. 统计碰撞情况
    in_degree = defaultdict(int)
    for _, child, _ in edges:
        in_degree[child] += 1
    collision_nodes = [(n, cnt) for n, cnt in in_degree.items() if cnt > 1]
    print(f"\n碰撞节点（入度>1）：{collision_nodes}")

    # 4. 绘制树状图
    print("\n绘制碰撞树...")
    plot_aes_tree(layers, edges, s, t)