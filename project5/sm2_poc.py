import hashlib, secrets, time
from typing import Tuple, Optional

# ==============================
# SM2 曲线参数（GM/T 0003.5-2012）
# ==============================
p = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
a = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
b = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
gx = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
gy = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
n  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)

O = (None, None)  # 无穷远点

def is_on_curve(P):
    if P == O: return True
    x, y = P
    return (y*y - (x*x*x + a*x + b)) % p == 0

# ----------------
# 基础数论/点运算
# ----------------
def mod_inv(x: int, m: int) -> int:
    # Python3.8+ 支持 pow(x, -1, m)
    return pow(x, -1, m)

def affine_add(P, Q):
    if P == O: return Q
    if Q == O: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return O
        # doubling
        lam = (3*x1*x1 + a) * mod_inv(2*y1 % p, p) % p
    else:
        lam = (y2 - y1) * mod_inv((x2 - x1) % p, p) % p
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3, y3)

def affine_double(P):
    return affine_add(P, P)

def affine_mul(k: int, P):
    R = O
    Q = P
    while k > 0:
        if k & 1:
            R = affine_add(R, Q)
        Q = affine_double(Q)
        k >>= 1
    return R

# ----------------
# “SM3”占位（演示）
# ----------------
def sm3_hash(msg: bytes) -> bytes:
    # 演示用：真实系统请替换为 SM3
    return hashlib.sha256(msg).digest()

def ZA_hash(ID: bytes, PxPy) -> bytes:
    x, y = PxPy
    ENTLa = (len(ID) * 8).to_bytes(2, 'big')
    a_bytes  = a.to_bytes(32, 'big')
    b_bytes  = b.to_bytes(32, 'big')
    gx_bytes = gx.to_bytes(32, 'big')
    gy_bytes = gy.to_bytes(32, 'big')
    px_bytes = x.to_bytes(32, 'big')
    py_bytes = y.to_bytes(32, 'big')
    msg = ENTLa + ID + a_bytes + b_bytes + gx_bytes + gy_bytes + px_bytes + py_bytes
    return sm3_hash(msg)

# -------------
# 密钥与签名
# -------------
def keygen():
    d = secrets.randbelow(n - 1) + 1
    P = affine_mul(d, (gx, gy))
    assert is_on_curve(P)
    return d, P

def sm2_sign(msg: bytes, d: int, k: Optional[int] = None) -> Tuple[int,int,int]:
    """
    返回 (r,s,k_used)，k 可选：若提供则强制使用（用于 PoC），否则随机。
    """
    if k is None:
        k = secrets.randbelow(n - 1) + 1
    # 1) 计算 ZA 和 e
    ID = b'1234567812345678'
    P  = affine_mul(d, (gx, gy))
    ZA = ZA_hash(ID, P)
    e  = int.from_bytes(sm3_hash(ZA + msg), 'big') % n

    # 2) 计算 kG 和 r
    x1, y1 = affine_mul(k, (gx, gy))
    r = (e + x1) % n
    if r == 0 or r + k == n:
        # 按标准这里应重新取 k；PoC 里简单抛错
        raise ValueError("Bad k produced r==0 or r+k==n")

    # 3) 计算 s = (k - r d) * (1+d)^-1
    s = ((k - r * d) % n) * mod_inv((1 + d) % n, n) % n
    if s == 0:
        raise ValueError("Bad s==0")
    return r, s, k

def sm2_verify(msg: bytes, P, sig: Tuple[int,int]) -> bool:
    r, s = sig
    if not (1 <= r <= n-1 and 1 <= s <= n-1):
        return False
    ID = b'1234567812345678'
    ZA = ZA_hash(ID, P)
    e  = int.from_bytes(sm3_hash(ZA + msg), 'big') % n
    t  = (r + s) % n
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
# 攻击 A：重复 k 恢复私钥
# -------------------------
def recover_d_reused_k(sig1: Tuple[int,int], sig2: Tuple[int,int]) -> int:
    r1, s1 = sig1
    r2, s2 = sig2
    num = (s1 - s2) % n
    den = (r2 - r1 - (s1 - s2)) % n
    if den == 0:
        raise ValueError("不可逆：分母为 0")
    d = (num * mod_inv(den, n)) % n
    return d

# -------------------------
# 攻击 B：已知 k 恢复私钥
# -------------------------
def recover_d_known_k(sig: Tuple[int,int], k: int) -> int:
    r, s = sig
    den = (s + r) % n
    if den == 0:
        raise ValueError("不可逆：s + r == 0")
    d = ((k - s) % n) * mod_inv(den, n) % n
    return d

# ===============
# 自检 / 演示 PoC
# ===============
def demo():
    print("生成密钥...")
    d, P = keygen()
    print("真实私钥 d =", hex(d))

    # ---------- PoC-A: 重复 k ----------
    print("\n[PoC-A] 重复使用同一个 k")
    k_fixed = secrets.randbelow(n - 1) + 1
    m1 = b"message one for reused-k"
    m2 = b"message two for reused-k"
    r1, s1, k1 = sm2_sign(m1, d, k=k_fixed)
    r2, s2, k2 = sm2_sign(m2, d, k=k_fixed)
    assert k1 == k2 == k_fixed

    # 验签
    assert sm2_verify(m1, P, (r1, s1))
    assert sm2_verify(m2, P, (r2, s2))

    # 恢复 d
    d_rec = recover_d_reused_k((r1,s1), (r2,s2))
    print("恢复出的 d (reused-k) =", hex(d_rec))
    print("PoC-A 成功？", d_rec == d)

    # ---------- PoC-B: 已知 k ----------
    print("\n[PoC-B] 已知/泄露 k 的场景")
    m3 = b"single message where k is known"
    r3, s3, k3 = sm2_sign(m3, d)  # 正常签名，但我们记录了 k3
    assert sm2_verify(m3, P, (r3, s3))

    d_rec2 = recover_d_known_k((r3, s3), k3)
    print("恢复出的 d (known-k)  =", hex(d_rec2))
    print("PoC-B 成功？", d_rec2 == d)

    # 一致性再检：用恢复的 d 还原公钥
    if d_rec == d:
        P1 = affine_mul(d_rec, (gx, gy))
        print("公钥一致性(复原自 PoC-A)：", P1 == P)
    if d_rec2 == d:
        P2 = affine_mul(d_rec2, (gx, gy))
        print("公钥一致性(复原自 PoC-B)：", P2 == P)

if __name__ == "__main__":
    demo()
