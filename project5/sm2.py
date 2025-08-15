# SM2 implementation with performance comparison of different ECC scalar multiplication algorithms.
# - Baseline: affine coordinates, double-and-add scalar multiplication
# - Improvement 1: Jacobian coordinates (avoid inverses)
# - Improvement 2: Windowed wNAF scalar multiplication
# - Improvement 3: Montgomery ladder (constant-time)
#
# The code implements:
#  - SM2 curve parameters (GM/T 0003.5-2012)
#  - Point operations (affine & jacobian)
#  - Scalar multiplication variants
#  - Key generation, signing (SM2), verification
#  - Performance tests comparing the time for keygen, sign, verify across methods
#
# Note: This is a pedagogical implementation in pure Python for clarity and benchmarking.
# It is NOT optimized for production use. Use well-tested libraries (e.g., OpenSSL, gmssl) for real crypto.
import os, sys, time, hashlib, secrets, math
from dataclasses import dataclass
from typing import Optional, Tuple

# ---------- SM2 domain parameters (GM/T 0003.5-2012) ----------
# Values taken from standard references (public domain)
p = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
a = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
b = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
gx = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
gy = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
n = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
h = 1

# sanity check: ensure point is on curve
def is_on_curve(x: int, y: int) -> bool:
    return (y * y - (x * x * x + a * x + b)) % p == 0

assert is_on_curve(gx, gy), "Base point not on curve (params wrong)"

# ---------- Basic modular arithmetic ----------
def mod_inv(x: int, m: int = p) -> int:
    # Python's pow with -1 doesn't work; use extended gcd via pow(x, m-2, m) only if m is prime
    # p is prime here, so:
    return pow(x, m - 2, m)

def mod_sqrt(a_val: int, p_mod: int = p) -> Optional[int]:
    # Not used in this implementation, placeholder
    return None

# ---------- Affine point representation ----------
AffinePoint = Tuple[int, int]
O = (None, None)  # point at infinity

def affine_add(P: AffinePoint, Q: AffinePoint) -> AffinePoint:
    if P == O: return Q
    if Q == O: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return O
        # point doubling
        lam = (3 * x1 * x1 + a) * mod_inv(2 * y1, p) % p
    else:
        lam = (y2 - y1) * mod_inv(x2 - x1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def affine_mul(k: int, P: AffinePoint) -> AffinePoint:
    # baseline double-and-add (MSB-first)
    R = O
    Q = P
    while k > 0:
        if k & 1:
            R = affine_add(R, Q)
        Q = affine_add(Q, Q)
        k >>= 1
    return R

# ---------- Jacobian coordinates for faster operations ----------
# Jacobian point is (X, Y, Z) representing affine (X/Z^2, Y/Z^3)
JacPoint = Tuple[int, int, int]
J_O = (0, 1, 0)  # point at infinity in Jacobian

def to_jac(P: AffinePoint) -> JacPoint:
    if P == O: return J_O
    x, y = P
    return (x, y, 1)

def to_affine(J: JacPoint) -> AffinePoint:
    X, Y, Z = J
    if Z == 0:
        return O
    z2 = pow(Z, 2, p)
    z3 = (z2 * Z) % p
    x = (X * mod_inv(z2, p)) % p
    y = (Y * mod_inv(z3, p)) % p
    return (x, y)

def jac_double(P: JacPoint) -> JacPoint:
    X1, Y1, Z1 = P
    if Z1 == 0 or Y1 == 0:
        return J_O
    S = (4 * X1 * pow(Y1, 2, p)) % p
    M = (3 * pow(X1, 2, p) + a * pow(Z1, 4, p)) % p
    X3 = (pow(M, 2, p) - 2 * S) % p
    Y3 = (M * (S - X3) - 8 * pow(Y1, 4, p)) % p
    Z3 = (2 * Y1 * Z1) % p
    return (X3, Y3, Z3)

def jac_add(P: JacPoint, Q: JacPoint) -> JacPoint:
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q
    if Z1 == 0: return (X2, Y2, Z2)
    if Z2 == 0: return (X1, Y1, Z1)
    U1 = (X1 * pow(Z2, 2, p)) % p
    U2 = (X2 * pow(Z1, 2, p)) % p
    S1 = (Y1 * pow(Z2, 3, p)) % p
    S2 = (Y2 * pow(Z1, 3, p)) % p
    if U1 == U2:
        if S1 != S2:
            return J_O
        else:
            return jac_double(P)
    H = (U2 - U1) % p
    R = (S2 - S1) % p
    H2 = (H * H) % p
    H3 = (H2 * H) % p
    U1H2 = (U1 * H2) % p
    X3 = (R * R - H3 - 2 * U1H2) % p
    Y3 = (R * (U1H2 - X3) - S1 * H3) % p
    Z3 = (H * Z1 * Z2) % p
    return (X3, Y3, Z3)

def jac_mul(k: int, P_aff: AffinePoint) -> AffinePoint:
    # convert to jacobian and do double-and-add in jacobian coordinates
    P = to_jac(P_aff)
    R = J_O
    while k > 0:
        if k & 1:
            R = jac_add(R, P)
        P = jac_double(P)
        k >>= 1
    return to_affine(R)

# ---------- wNAF windowed scalar multiplication ----------
def int_to_wnaf(k: int, width: int) -> list:
    # return signed-digit representation (wNAF)
    if k == 0:
        return [0]
    w = width
    pow2w = 1 << w
    mask = pow2w - 1
    naf = []
    while k > 0:
        if k & 1:
            z = k & mask
            if z & (1 << (w - 1)):
                z = z - pow2w
            naf.append(z)
            k = k - z
        else:
            naf.append(0)
        k >>= 1
    return naf

def precompute_window(P: AffinePoint, width: int) -> dict:
    # precompute odd multiples: P,3P,5P,... up to 2^{w-1}-1
    max_odd = (1 << (width - 1)) - 1
    table = {}
    table[1] = P
    if max_odd >= 3:
        table[3] = affine_add(P, affine_add(P, P))  # 3P = P + 2P (but inefficient)
        # build by adding 2P repeatedly is slow; use doubling then addition
        # better build general but for simplicity we compute sequentially
        cur = table[1]
        for i in range(3, max_odd + 1, 2):
            cur = affine_add(cur, affine_add(P, P)) if i != 3 else affine_add(P, affine_add(P, P))
            table[i] = cur
    return table

def wnaf_mul(k: int, P: AffinePoint, width: int = 5) -> AffinePoint:
    naf = int_to_wnaf(k, width)
    pre = {}
    # precompute odd multiples up to 2^{w-1}
    max_odd = (1 << (width - 1)) - 1
    # build them via repeated addition (not optimal but OK for demo)
    pre[1] = P
    if max_odd >= 3:
        twoP = affine_add(P, P)
        for i in range(3, max_odd + 1, 2):
            pre[i] = affine_add(pre[i - 2], twoP) if (i - 2) in pre else affine_add(pre[1], twoP)
    R = O
    for d in reversed(naf):
        # every step do a doubling
        R = affine_add(R, R)
        if d != 0:
            if d > 0:
                R = affine_add(R, pre[abs(d)])
            else:
                # negative: add -pre[abs(d)]
                x, y = pre[abs(d)]
                R = affine_add(R, (x, (-y) % p))
    return R

# ---------- Montgomery ladder (constant-time) ----------
def montgomery_ladder_mul(k: int, P: AffinePoint) -> AffinePoint:
    # simple implementation of montgomery ladder using affine ops (not fastest but constant-time pattern)
    R0 = O
    R1 = P
    for i in reversed(range(k.bit_length())):
        bit = (k >> i) & 1
        if bit == 0:
            R1 = affine_add(R0, R1)
            R0 = affine_add(R0, R0)
        else:
            R0 = affine_add(R0, R1)
            R1 = affine_add(R1, R1)
    return R0

# ---------- SM2 signature (simplified) ----------
# SM2 signature uses ZA = Hash(ENTL || ID || a || b || Gx || Gy || Px || Py) then hash ZA || M
def sm3_hash(msg: bytes) -> bytes:
    # SM3 is a Chinese hash standard; for demonstration here we'll use SHA256 as a placeholder
    # NOTE: For conformance, replace with a SM3 implementation.
    return hashlib.sha256(msg).digest()

def ZA_hash(ID: bytes, Px: AffinePoint) -> bytes:
    # construct the standard ZA using domain parameters; ID typically b'1234567812345678'
    ENTLa = (len(ID) * 8).to_bytes(2, 'big')
    a_bytes = a.to_bytes(32, 'big')
    b_bytes = b.to_bytes(32, 'big')
    gx_bytes = gx.to_bytes(32, 'big')
    gy_bytes = gy.to_bytes(32, 'big')
    px_bytes = Px[0].to_bytes(32, 'big')
    py_bytes = Px[1].to_bytes(32, 'big')
    msg = ENTLa + ID + a_bytes + b_bytes + gx_bytes + gy_bytes + px_bytes + py_bytes
    return sm3_hash(msg)

def sm2_sign(msg: bytes, d: int, k_func, scalar_mul_func) -> Tuple[int,int]:
    # k_func: function to get ephemeral k (returns integer in [1, n-1])
    # scalar_mul_func: function(k, P) -> AffinePoint for scalar mult
    ID = b'1234567812345678'
    Px = scalar_mul_func(d, (gx, gy))
    ZA = ZA_hash(ID, Px)
    e = int.from_bytes(sm3_hash(ZA + msg), 'big') % n
    while True:
        k = k_func()
        x1, y1 = scalar_mul_func(k, (gx, gy))
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        s = (mod_inv(1 + d, n) * (k - r * d)) % n
        if s == 0:
            continue
        return (r, s)

def sm2_verify(msg: bytes, P: AffinePoint, signature: Tuple[int,int], scalar_mul_func) -> bool:
    r, s = signature
    if not (1 <= r <= n-1 and 1 <= s <= n-1):
        return False
    ID = b'1234567812345678'
    ZA = ZA_hash(ID, P)
    e = int.from_bytes(sm3_hash(ZA + msg), 'big') % n
    t = (r + s) % n
    if t == 0:
        return False
    x1, y1 = scalar_mul_func(s, (gx, gy))
    x2, y2 = scalar_mul_func(t, P)
    xr, yr = affine_add((x1,y1), (x2,y2))
    R = (e + xr) % n
    return R == r

# ---------- Helpers ----------
def random_k() -> int:
    # secure random in [1, n-1]
    return secrets.randbelow(n - 1) + 1

# deterministic simple RNG for reproducibility in some tests
def make_k_func():
    def kgen():
        return random_k()
    return kgen

# ---------- Key generation ----------
def keygen(k_scalar_mul=affine_mul):
    d = secrets.randbelow(n - 1) + 1
    P = k_scalar_mul(d, (gx, gy))
    return d, P

# ---------- Performance testing suite ----------
def time_operation(func, *args, loops=50):
    # Warmup
    for _ in range(3):
        func(*args)
    t0 = time.perf_counter()
    for _ in range(loops):
        func(*args)
    t1 = time.perf_counter()
    return (t1 - t0) / loops

# Wrap scalar multiplication for uniform interface
def scalar_affine(k, P): return affine_mul(k, P)
def scalar_jac(k, P): return jac_mul(k, P)
def scalar_wnaf(k, P): return wnaf_mul(k, P, width=5)
def scalar_mont(k, P): return montgomery_ladder_mul(k, P)

# ---------- Run benchmark ----------
def benchmark():
    baseline = {
        '未优化SM2(仿射坐标+双加)': scalar_affine
    }
    optimized = {
        '优化1:雅可比坐标(双加)': scalar_jac,
        '优化2:wNAF窗口法': scalar_wnaf,
        '优化3:蒙哥马利阶梯法': scalar_mont
    }

    k_test = secrets.randbelow(n - 1) + 1
    msg = 'SM2实现性能测试的基准消息'.encode('utf-8')
    results = {}

    loops_scalar = 40
    loops_keygen = 40
    loops_sign_verify = 16

    print("===== 基准测试：未优化 SM2 =====")
    for name, func in baseline.items():
        results[name] = {}
        # 标量乘法
        t = time_operation(func, k_test, (gx, gy), loops=loops_scalar)
        results[name]['标量乘法(s)'] = t
        print(f"{name}: 标量乘法 {t*1000:.3f} ms")

        # 密钥生成
        t = time_operation(lambda: keygen(k_scalar_mul=func), loops=loops_keygen)
        results[name]['密钥生成(s)'] = t
        print(f"{name}: 密钥生成 {t*1000:.3f} ms")

        # 签名+验证
        def sign_then_verify():
            d, P = keygen(k_scalar_mul=func)
            kfunc = make_k_func()
            sig = sm2_sign(msg, d, kfunc, func)
            ok = sm2_verify(msg, P, sig, func)
            if not ok:
                raise ValueError(f"{name} 签名验证失败")
        t = time_operation(sign_then_verify, loops=loops_sign_verify)
        results[name]['签名验证(s)'] = t
        print(f"{name}: 签名+验证 {t*1000:.3f} ms")

    print("\n===== 基准测试：优化后的 SM2 =====")
    for name, func in optimized.items():
        results[name] = {}
        # 标量乘法
        t = time_operation(func, k_test, (gx, gy), loops=loops_scalar)
        results[name]['标量乘法(s)'] = t
        print(f"{name}: 标量乘法 {t*1000:.3f} ms")

        # 密钥生成
        t = time_operation(lambda: keygen(k_scalar_mul=func), loops=loops_keygen)
        results[name]['密钥生成(s)'] = t
        print(f"{name}: 密钥生成 {t*1000:.3f} ms")

        # 签名+验证
        def sign_then_verify():
            d, P = keygen(k_scalar_mul=func)
            kfunc = make_k_func()
            sig = sm2_sign(msg, d, kfunc, func)
            ok = sm2_verify(msg, P, sig, func)
            if not ok:
                raise ValueError(f"{name} 签名验证失败")
        t = time_operation(sign_then_verify, loops=loops_sign_verify)
        results[name]['签名验证(s)'] = t
        print(f"{name}: 签名+验证 {t*1000:.3f} ms")

    print("\n===== 性能测试汇总(秒) =====")
    for k, v in results.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    res = benchmark()


