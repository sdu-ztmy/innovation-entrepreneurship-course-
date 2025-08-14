import hashlib
import random
import math
from typing import List, Tuple

def is_probable_prime(n: int, k: int = 8) -> bool:
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits: int) -> int:
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(n):
            return n

def egcd(a, b):
    if b == 0: return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def invmod(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

def lcm(a, b):
    return a // math.gcd(a, b) * b

class PaillierPublicKey:
    def __init__(self, n: int, g: int):
        self.n = n
        self.g = g
        self.nsqr = n * n

class PaillierPrivateKey:
    def __init__(self, lam: int, mu: int):
        self.lam = lam
        self.mu = mu

def paillier_keygen(bits=512):
    p = gen_prime(bits//2)
    q = gen_prime(bits//2)
    n = p * q
    g = n + 1
    lam = lcm(p-1, q-1)
    nsqr = n * n
    x = pow(g, lam, nsqr)
    Lx = (x - 1) // n
    mu = invmod(Lx, n)
    return PaillierPublicKey(n, g), PaillierPrivateKey(lam, mu), (p,q)

def paillier_encrypt(pub: PaillierPublicKey, m: int, r=None) -> int:
    n = pub.n
    nsqr = pub.nsqr
    if r is None:
        while True:
            r = random.randrange(1, n)
            if math.gcd(r, n) == 1:
                break
    c = (pow(pub.g, m, nsqr) * pow(r, n, nsqr)) % nsqr
    return c

def paillier_decrypt(pub: PaillierPublicKey, priv: PaillierPrivateKey, c: int) -> int:
    n = pub.n
    nsqr = pub.nsqr
    x = pow(c, priv.lam, nsqr)
    Lx = (x - 1) // n
    m = (Lx * priv.mu) % n
    return m

def paillier_add(pub: PaillierPublicKey, c1: int, c2: int) -> int:
    return (c1 * c2) % pub.nsqr

def paillier_scalar_mul(pub: PaillierPublicKey, c: int, k: int) -> int:
    return pow(c, k, pub.nsqr)

def paillier_refresh(pub: PaillierPublicKey, c: int) -> int:
    zero_enc = paillier_encrypt(pub, 0)
    return (c * zero_enc) % pub.nsqr

def sha256_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), 'big')

class Group:
    def __init__(self, p: int, g: int):
        self.p = p
        self.g = g

    def hash_to_group(self, uid: str) -> int:
        h = sha256_int(uid.encode('utf-8'))
        exp = h % (self.p - 1)
        return pow(self.g, exp, self.p)

class Party1:
    def __init__(self, ids: List[str], group: Group):
        self.ids = ids[:]
        self.group = group
        self.k1 = random.randrange(2, group.p - 1)

    def round1_send(self):
        out = []
        for v in self.ids:
            hv = self.group.hash_to_group(v)
            out.append(pow(hv, self.k1, self.group.p))
        random.shuffle(out)
        return out

    def round3_receive_and_process(self, Z_list: List[int], enc_pairs: List[Tuple[int,int]], paillier_pub: PaillierPublicKey):
        firsts = []
        for (h_wj_k2, aenc_tj) in enc_pairs:
            firsts.append((pow(h_wj_k2, self.k1, self.group.p), aenc_tj))

        setZ = set(Z_list)
        intersection_cipher_sum = None
        for (h_wj_k1k2, aenc_tj) in firsts:
            if h_wj_k1k2 in setZ:
                if intersection_cipher_sum is None:
                    intersection_cipher_sum = aenc_tj
                else:
                    intersection_cipher_sum = paillier_add(paillier_pub, intersection_cipher_sum, aenc_tj)

        if intersection_cipher_sum is None:
            intersection_cipher_sum = paillier_encrypt(paillier_pub, 0)

        intersection_cipher_sum = paillier_refresh(paillier_pub, intersection_cipher_sum)
        return intersection_cipher_sum

class Party2:
    def __init__(self, pairs: List[Tuple[str, int]], group: Group):
        self.pairs = pairs[:]
        self.group = group
        self.k2 = random.randrange(2, group.p - 1)
        self.paillier_pub, self.paillier_priv, _ = paillier_keygen(bits=512)

    def round2_receive_and_send(self, list_from_p1: List[int]):
        Z = [pow(x, self.k2, self.group.p) for x in list_from_p1]
        random.shuffle(Z)
        enc_pairs = []
        for (w, t) in self.pairs:
            h_w = self.group.hash_to_group(w)
            h_w_k2 = pow(h_w, self.k2, self.group.p)
            aenc_t = paillier_encrypt(self.paillier_pub, t)
            enc_pairs.append((h_w_k2, aenc_t))
        random.shuffle(enc_pairs)
        return Z, enc_pairs, self.paillier_pub

    def final_decrypt(self, c: int) -> int:
        return paillier_decrypt(self.paillier_pub, self.paillier_priv, c)

def demo():
    print("DDH-based Private Intersection-Sum Protocol Demo\n")
    group_bits = 512
    p = gen_prime(group_bits)
    g = 2
    group = Group(p, g)
    print("Group modulus p (bits={}): generated".format(group_bits))

    P1_ids = ["alice@example", "bob@example", "carol@example", "dave@example"]
    P2_pairs = [("bob@example", 5), ("erin@example", 7), ("carol@example", 3), ("mallory@example", 11)]

    id_to_weight = {w: t for (w, t) in P2_pairs}
    direct_J = [v for v in P1_ids if v in id_to_weight]
    direct_sum = sum(id_to_weight[v] for v in direct_J)

    print("P1 ids:", P1_ids)
    print("P2 pairs:", P2_pairs)
    print("Direct intersection:", direct_J, "Direct sum:", direct_sum)

    p1 = Party1(P1_ids, group)
    p2 = Party2(P2_pairs, group)

    msg1 = p1.round1_send()

    Z_list, enc_pairs, paillier_pub = p2.round2_receive_and_send(msg1)

    c_sum = p1.round3_receive_and_process(Z_list, enc_pairs, paillier_pub)

    recovered_sum = p2.final_decrypt(c_sum)

    print("P2 decrypted intersection-sum:", recovered_sum)
    assert recovered_sum == direct_sum, "Mismatch! Protocol failed to recover correct sum."
    print("Success: recovered sum equals direct sum.")

if __name__ == "__main__":
    demo()