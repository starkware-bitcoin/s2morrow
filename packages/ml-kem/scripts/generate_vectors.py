#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Reference Python implementation matching the simplified Cairo ML-KEM.
Generates deterministic test vectors for NTT and key encapsulation.
"""

from dataclasses import dataclass
from typing import List, Tuple

Q = 3329
N = 256
K = 2
INV_N = 3327  # 256^{-1} mod Q

ZETAS = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127, 1855, 1468, 573,
    2004, 264, 383, 1511, 1738, 45, 647, 1455, 3029, 1628, 2003, 1710, 267, 1574, 165, 2783, 202,
    2230, 303, 1756, 1223, 652, 2777, 1003, 1227, 652, 1995, 2617, 149, 147, 1065, 601, 236, 631,
    207, 2503, 1701, 319, 1404, 2305, 695, 2057, 777, 379, 1550, 1007, 3152, 1099, 1605, 2788, 289,
    3381, 3165, 377, 1675, 2844, 1915, 2770, 1050, 1818, 591, 2184, 589, 397, 3632, 1663, 641, 1062,
    1649, 257, 2587, 1564, 1758, 1050, 2973, 2915, 3038, 1914, 2447, 36, 1319, 1590, 226, 1657, 345,
    2889, 2804, 142, 364, 202, 2295, 733, 102, 2129, 785, 391, 86, 1265, 1759, 1901, 329, 1223, 652,
    2777, 1003, 1227, 652, 1995, 2617, 149, 147, 1065, 601, 236, 631, 207, 2503,
]
INV_ZETAS = [
    826, 253, 282, 2014, 2698, 2107, 2551, 1902, 3127, 366, 327, 1186, 2124, 1104, 32, 1383, 2877,
    297, 2048, 1581, 1679, 1802, 1744, 3667, 1959, 2153, 1130, 3460, 2068, 665, 1252, 173, 1409, 245,
    1995, 1724, 3007, 596, 1129, 5, 128, 70, 1993, 1285, 1479, 456, 1786, 394, 981, 2303, 758, 1903,
    1360, 2531, 2133, 853, 2215, 605, 1506, 2601, 1219, 417, 2713, 2289, 2684, 2319, 1855, 2773,
    2771, 303, 925, 2268, 1693, 1917, 143, 1268, 697, 225, 2048, 1340, 1534, 511, 2841, 1449, 2036,
    1337, 1126, 2688, 595, 243, 207, 1880, 2151, 308, 841, 2200, 3075, 2774, 2647, 3167, 1372, 1171,
    827, 2171, 827, 193, 2284, 2122, 2344, 682, 3226, 1914, 3345, 3336, 1440, 1911, 552, 3445, 3274,
    1858, 193, 276, 1767, 2107,
]


def add_mod(a: int, b: int) -> int:
    return (a + b) % Q


def sub_mod(a: int, b: int) -> int:
    return (a + Q - b) % Q


def mul_mod(a: int, b: int) -> int:
    return (a * b) % Q


def ntt(poly: List[int]) -> List[int]:
    r = poly[:]
    k = 0
    length = N // 2
    while length >= 1:
        start = 0
        while start < N:
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = mul_mod(zeta, r[j + length])
                u = r[j]
                r[j] = add_mod(u, t)
                r[j + length] = sub_mod(u, t)
            start += 2 * length
        length //= 2
    return r


def intt(poly: List[int]) -> List[int]:
    r = poly[:]
    k = len(INV_ZETAS) - 1
    length = 1
    while length < N:
        start = 0
        while start < N:
            zeta = INV_ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                u = r[j]
                v = r[j + length]
                r[j] = add_mod(u, v)
                t = sub_mod(u, v)
                r[j + length] = mul_mod(zeta, t)
            start += 2 * length
        length *= 2
    return [mul_mod(x, INV_N) for x in r]


def mul_poly(a: List[int], b: List[int]) -> List[int]:
    return intt([mul_mod(x, y) for x, y in zip(ntt(a), ntt(b))])


def sample_poly(seed: int, nonce: int) -> List[int]:
    state = (seed << 16) | nonce
    out = []
    a = 6364136223846793005
    c = 1442695040888963407
    mask = (1 << 128) - 1
    for _ in range(N):
        state = (state * a + c) & mask
        out.append(state % Q)
    return out


def encode_message(msg: bytes) -> List[int]:
    coeffs = [0] * N
    idx = 0
    for byte in msg:
        for bit in range(8):
            if idx >= N:
                break
            coeffs[idx] = (byte >> bit) & 1
            idx += 1
    return coeffs


def derive_secret(poly: List[int]) -> bytes:
    acc = 0
    for c in poly:
        acc = (acc + c) & 0xFFFF_FFFF
        acc = (acc * 1664525 + 1013904223) % 0xFFFF_FFFF
    out = bytearray()
    for i in range(32):
        byte = (acc >> ((i % 4) * 8)) & 0xFF
        out.append(byte)
        acc = ((acc << 5) | (acc >> 27)) & 0xFFFF_FFFF
        acc ^= byte
    return bytes(out)


@dataclass
class PublicKey:
    a_ntt: List[List[int]]
    t_ntt: List[List[int]]


@dataclass
class SecretKey:
    s_ntt: List[List[int]]


def keygen(seed: int) -> Tuple[PublicKey, SecretKey]:
    a_ntt = []
    s_ntt = []
    t_ntt = []
    idx = 1
    for _ in range(K):
        a_row = ntt(sample_poly(seed, idx))
        idx += 1
        a_ntt.append(a_row)
    for _ in range(K):
        s = ntt(sample_poly(seed, idx))
        idx += 1
        e = sample_poly(seed, idx)
        idx += 1
        acc = [0] * N
        for col in range(K):
            acc = [add_mod(x, y) for x, y in zip(acc, intt([mul_mod(x, y) for x, y in zip(a_ntt[col], s)]))]
        t = [add_mod(x, y) for x, y in zip(acc, e)]
        t_ntt.append(ntt(t))
        s_ntt.append(s)
    return PublicKey(a_ntt, t_ntt), SecretKey(s_ntt)


def encapsulate(pk: PublicKey, seed: int):
    idx = 101
    r_ntt = []
    e1 = []
    for _ in range(K):
        r_ntt.append(ntt(sample_poly(seed, idx)))
        idx += 1
        e1.append(sample_poly(seed, idx))
        idx += 1
    e2 = sample_poly(seed, idx)
    msg = (seed.to_bytes(8, "big")) + bytes(24)  # pad to 32 bytes
    m_poly = encode_message(msg)

    u = []
    for row in range(K):
        acc = [0] * N
        for col in range(K):
            acc = [add_mod(x, y) for x, y in zip(acc, intt([mul_mod(x, y) for x, y in zip(pk.a_ntt[col], r_ntt[row])]))]
        u.append([add_mod(x, y) for x, y in zip(acc, e1[row])])

    acc = [0] * N
    for col in range(K):
        acc = [add_mod(x, y) for x, y in zip(acc, intt([mul_mod(x, y) for x, y in zip(pk.t_ntt[col], r_ntt[col])]))]
    v = [add_mod(add_mod(x, y), z) for x, y, z in zip(acc, e2, m_poly)]
    return (u, v), derive_secret(v)


def decapsulate(sk: SecretKey, ct):
    u, v = ct
    acc = v[:]
    for i in range(K):
        prod = [mul_mod(x, y) for x, y in zip(ntt(u[i]), sk.s_ntt[i])]
        acc = [sub_mod(x, y) for x, y in zip(acc, intt(prod))]
    return derive_secret(acc)


def main():
    seed = 0xBEEF_F00D_CAFE_BABE
    pk, sk = keygen(seed)
    ct, ss_enc = encapsulate(pk, seed + 7)
    ss_dec = decapsulate(sk, ct)
    print("ntt_roundtrip_ok:", intt(ntt(list(range(N)))) == [i % Q for i in range(N)])
    print("shared_secret_equal:", ss_enc == ss_dec)
    print("shared_secret_hex:", ss_dec.hex())


if __name__ == "__main__":
    main()

