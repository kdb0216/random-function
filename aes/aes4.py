import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import matplotlib.pyplot as plt
from collections import Counter


def int_to_bits(n, bit_length):
    return [int(x) for x in bin(n)[2:].zfill(bit_length)]


def bits_to_int(bits):
    return int("".join(map(str, bits)), 2)


def aes_encrypt_block(plaintext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def iterate(input_val, s, t, keys, consts):

    aes_bits = 128
    states = [0]*(t+1)

    states[0] = input_val

    bits = int_to_bits(input_val, s)
    current = bits + [0]*(aes_bits-s)

    for r in range(1,t+1):

        key = keys[r-1]
        const = consts[r-1]

        val = bits_to_int(current)
        b = val.to_bytes(16,'big')

        b = bytes(a ^ c for a,c in zip(b,const))

        enc = aes_encrypt_block(b,key)

        enc_int = int.from_bytes(enc,'big')
        enc_bits = int_to_bits(enc_int,aes_bits)

        current = enc_bits[:s] + [0]*(aes_bits-s)

        states[r] = bits_to_int(enc_bits[:s])

    return states


def count_preimage(target_states,s,t,x,keys,consts):

    total = 2**s

    result=[0]*(t+1)

    for i in range(1,t+1):

        P=set()

        for u in range(total):

            states=iterate(u,s,t,keys,consts)

            if states[i]==target_states[i]:

                if i>=x:
                    P.add(states[i-x])
                else:
                    P.add(states[0])

        result[i]=len(P)

    return result


if __name__=="__main__":

    s = 10   #输入比特数
    t = 32   #迭代轮数
    x = 16    #统计在x轮前的原像数

    keys=[secrets.token_bytes(16) for _ in range(t)]
    consts=[secrets.token_bytes(16) for _ in range(t)]

    # 随机输入
    m=secrets.randbelow(2**s)

    print("随机输入 m =",m)

    target_states=iterate(m,s,t,keys,consts)

    print("\n目标序列")

    for i in range(1,t+1):
        print("m",i,"=",target_states[i])

    print("\n开始统计原像...")

    result=count_preimage(target_states,s,t,x,keys,consts)

    print("\n统计结果")

    for i in range(1,t+1):
        print("m",i,"在",x,"轮前原像数:",result[i])

    xs = list(range(x, t + 1))
    ys = result[x:t + 1]

    plt.bar(xs, ys)

    plt.xlabel("round i")
    plt.ylabel(f"preimages {x} rounds before")
    plt.title("Preimage count of mi")

    plt.xticks(xs)

    plt.show()