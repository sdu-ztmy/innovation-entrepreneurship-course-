#!/usr/bin/env python3

import hashlib, secrets
from typing import Tuple

# -------------------------
# SM2 参数 (GM/T 0003.5-2012)
# -------------------------
p = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
a = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
b = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
gx = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
gy = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
n  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)

O = (None, None)

# -------------------------
# 基本数论与点运算（affine）
# -------------------------
def mod_inv(x: int, m: int) -> int:
    return pow(x, -1, m)

def is_on_curve(P):
    if P == O: return True
    x, y = P
    return (y*y - (x*x*x + a*x + b)) % p == 0

def affine_add(P, Q):
    if P == O: return Q
    if Q == O: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return O
        lam = (3*x1*x1 + a) * mod_inv((2*y1) % p, p) % p
    else:
        lam = (y2 - y1) * mod_inv((x2 - x1) % p, p) % p
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3, y3)

def affine_mul(k: int, P):
    R = O
    Q = P
    while k > 0:
        if k & 1:
            R = affine_add(R, Q)
        Q = affine_add(Q, Q)
        k >>= 1
    return R

# -------------------------
# Hash / ZA (占位)
# -------------------------
def sm3_hash(data: bytes) -> bytes:
    # 占位：用 SHA-256。真实系统请使用 SM3。
    return hashlib.sha256(data).digest()

def ZA_hash(ID: bytes, P):
    x, y = P
    ENTLa = (len(ID) * 8).to_bytes(2, 'big')
    a_bytes  = a.to_bytes(32, 'big')
    b_bytes  = b.to_bytes(32, 'big')
    gx_bytes = gx.to_bytes(32, 'big')
    gy_bytes = gy.to_bytes(32, 'big')
    px_bytes = x.to_bytes(32, 'big')
    py_bytes = y.to_bytes(32, 'big')
    return sm3_hash(ENTLa + ID + a_bytes + b_bytes + gx_bytes + gy_bytes + px_bytes + py_bytes)

# -------------------------
# SM2 签名 / 验签 (简化)
# -------------------------
def sm2_sign_with_k(msg: bytes, d: int, k: int) -> Tuple[int,int]:
    """ 使用指定的 k 返回 (r, s)；若产生无效 r/s 则抛错（PoC 简化） """
    ID = b'1234567812345678'
    P = affine_mul(d, (gx, gy))
    ZA = ZA_hash(ID, P)
    e = int.from_bytes(sm3_hash(ZA + msg), 'big') % n

    x1, y1 = affine_mul(k, (gx, gy))
    r = (e + x1) % n
    if r == 0 or r + k == n:
        raise ValueError("bad r (rare) - choose another k")
    s = ((k - r * d) % n) * mod_inv((1 + d) % n, n) % n
    if s == 0:
        raise ValueError("bad s (rare)")
    return r, s

def sm2_verify(msg: bytes, P, sig: Tuple[int,int]) -> bool:
    r, s = sig
    if not (1 <= r <= n-1 and 1 <= s <= n-1):
        return False
    ID = b'1234567812345678'
    ZA = ZA_hash(ID, P)
    e = int.from_bytes(sm3_hash(ZA + msg), 'big') % n
    t = (r + s) % n
    if t == 0:
        return False
    x1, y1 = affine_mul(s, (gx, gy))
    x2, y2 = affine_mul(t, P)
    if x1 is None or x2 is None:
        return False
    xr, yr = affine_add((x1,y1), (x2,y2))
    R = (e + xr) % n
    return R == r

# -------------------------
# 攻击：重复 k 恢复私钥，并伪造新签名
# -------------------------
def recover_privkey_from_reused_k(r1, s1, r2, s2) -> int:
    """
    从两条使用相同 k 的签名 (r1,s1) 与 (r2,s2) 恢复 d
    推导（参见文档）：
      (s1 - s2)*(1+d) ≡ (r2 - r1)*d  (mod n)
    => d ≡ (s1 - s2) * (r2 - r1 - (s1 - s2))^{-1}  (mod n)
    """
    num = (s1 - s2) % n
    den = (r2 - r1 - (s1 - s2)) % n
    if den % n == 0:
        raise ValueError("不可逆：分母为 0 mod n")
    return (num * mod_inv(den, n)) % n

def forge_signature_with_recovered_d(msg: bytes, d_rec: int) -> Tuple[int,int]:
    """用恢复出的私钥直接对任意 msg 生成合法 SM2 签名（正常签名流程，随机 k）"""
    # 这里使用正常签名流程（随机 k）；如果需要，可使用指定 k。
    k = secrets.randbelow(n - 1) + 1
    return sm2_sign_with_k(msg, d_rec, k)

# -------------------------
# Demo: 完整流程（实验环境）
# -------------------------
def demo():
    # 1. 生成实验密钥（仅用于 demo）
    d = secrets.randbelow(n - 1) + 1
    P = affine_mul(d, (gx, gy))
    assert is_on_curve(P)
    print("[*] 生成实验密钥对")
    print("    私钥 d (hex):", hex(d))
    print("    公钥 P: (x,y) = (0x%s, 0x%s)" % (hex(P[0])[2:], hex(P[1])[2:]))
    print()

    # 2. 选择固定 k（模拟开发/实现失误导致的重复使用）
    k_fixed = secrets.randbelow(n - 1) + 1
    print("[*] 使用同一个 k（模拟漏洞）：k =", hex(k_fixed))
    m1 = b"Message #1: payment to Alice"
    m2 = b"Message #2: payment to Bob"

    r1, s1 = sm2_sign_with_k(m1, d, k_fixed)
    r2, s2 = sm2_sign_with_k(m2, d, k_fixed)
    print("[*] 签名1 (r1,s1):", hex(r1), hex(s1))
    print("[*] 签名2 (r2,s2):", hex(r2), hex(s2))

    # 3. 验签确认两条签名对公钥有效
    ok1 = sm2_verify(m1, P, (r1, s1))
    ok2 = sm2_verify(m2, P, (r2, s2))
    print("[*] 验签结果: sig1 ok?", ok1, ", sig2 ok?", ok2)

    # 4. 恢复私钥
    d_rec = recover_privkey_from_reused_k(r1, s1, r2, s2)
    print("[*] 恢复出的私钥 d_rec:", hex(d_rec))
    print("[*] 恢复正确？", d_rec == d)

    # 5. 用恢复的私钥伪造对任意消息的签名
    target_msg = b"Forged message: redirect funds to attacker (demo only)"
    # 直接使用恢复的私钥签名（此处正常流程内会随机选 k）
    forged_r, forged_s = forge_signature_with_recovered_d(target_msg, d_rec)
    print("[*] 用恢复的私钥生成的伪造签名 (r,s):", hex(forged_r), hex(forged_s))
    ok_forged = sm2_verify(target_msg, P, (forged_r, forged_s))
    print("[*] 伪造签名通过验证？", ok_forged)

    # 6. 额外检查：用恢复的 d 还原公钥
    P_rec = affine_mul(d_rec, (gx, gy))
    print("[*] 恢复私钥对应公钥与原公钥一致？", P_rec == P)

if __name__ == "__main__":
    import secrets, hashlib
    demo()
