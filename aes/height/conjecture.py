import random
from collections import defaultdict

# ===============================
# 参数设置（可以调）
# ===============================
l = 22                  # 状态bit数（不要太大，否则跑不动）
N = 1 << l              # 节点总数
target_t = 16           # 想收集 2^t 个节点
target_size = 1 << target_t

MAX_LAMBDA = int((2 ** (l/2)) / l)

# ===============================
# 1. 生成随机函数 f
# ===============================
f = [random.randrange(N) for _ in range(N)]

# ===============================
# 2. 计算链 + height
# ===============================
def process_chain(start, Y_set, Y_height):
    visited = {}
    chain = []

    x = start
    step = 0

    while True:
        if x in visited:
            # case 1: cycle
            cycle_start = visited[x]
            end_type = "cycle"
            break

        if x in Y_set:
            # case 2: attach to existing Y
            cycle_start = len(chain)
            end_type = "attach"
            attach_node = x
            break

        visited[x] = step
        chain.append(x)
        x = f[x]
        step += 1

    height = {}
    length = len(chain)

    # ===========================
    # 计算 height
    # ===========================

    if end_type == "cycle":
        # cycle nodes height = 0
        for i in reversed(range(length)):
            if i >= cycle_start:
                height[chain[i]] = 0
            else:
                height[chain[i]] = height[chain[i+1]] + 1

    else:  # attach
        # 最后一个点接到已有节点
        height_last = Y_height[attach_node] + 1
        height[chain[-1]] = height_last

        for i in reversed(range(length - 1)):
            height[chain[i]] = height[chain[i+1]] + 1

    return chain, height


# ===============================
# 3. 构建 Y
# ===============================
Y_set = set()
Y_lambda = defaultdict(int)
Y_height = {}

while len(Y_set) < target_size:
    start = random.randrange(N)
    if start in Y_set:
        continue

    chain, height = process_chain(start, Y_set, Y_height)

    for node in chain:
        if node not in Y_set:
            Y_set.add(node)
            Y_height[node] = height[node]
            lam = height[node]
            Y_lambda[lam] += 1

    print(f"Collected: {len(Y_set)}/{target_size}")

# ===============================
# 4. 统计结果
# ===============================
print("\n==== Height Distribution ====")

expected = 2 ** (target_t - l/2)
print(f"Expected scale ≈ {expected:.2f}\n")

for lam in range(1, int(MAX_LAMBDA)+1):
    count = Y_lambda.get(lam, 0)
    print(f"λ={lam:2d}  |Y_λ|={count:6d}  ratio={count/expected:.2f}")