def prf(input_bits: str, s: int) -> str:
    """伪随机函数"""
    if len(input_bits) != s:
        raise ValueError(f"输入必须是 {s} 位")
    import hashlib
    data = input_bits.encode('utf-8')
    h = hashlib.md5(data).hexdigest()
    bits = bin(int(h, 16))[2:].zfill(128)[:s]
    return bits

print(prf("11001101", 8))