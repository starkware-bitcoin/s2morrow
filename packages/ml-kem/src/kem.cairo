// SPDX-License-Identifier: MIT

//! Simplified ML-KEM (Kyber-like) key share and envelope encryption.

use crate::params::{K, N};
use crate::poly::{Poly, add, encode_message, intt_inplace, ntt_inplace, pointwise_mul, sub};
use crate::sampler::sample_poly;

#[derive(Drop, Clone, Serde, PartialEq, Debug)]
pub struct PublicKey {
    pub a_ntt: Array<Poly>, // K rows
    pub t_ntt: Array<Poly> // K columns
}

#[derive(Drop, Clone, Serde, PartialEq, Debug)]
pub struct SecretKey {
    pub s_ntt: Array<Poly>,
}

#[derive(Drop, Clone, Serde, PartialEq, Debug)]
pub struct Ciphertext {
    pub u: Array<Poly>,
    pub v: Poly,
}

#[derive(Drop, Clone, Serde, PartialEq, Debug)]
pub struct SharedSecret {
    pub bytes: Array<u8>,
}

/// Key generation using deterministic seeds (for reproducible tests).
pub fn keygen(seed: u64) -> (PublicKey, SecretKey) {
    let mut a_ntt: Array<Poly> = array![];
    let mut s_ntt: Array<Poly> = array![];
    let mut t_ntt: Array<Poly> = array![];

    // Expand matrix A and noise polynomials deterministically.
    let mut idx: u16 = 1;
    let mut row: usize = 0;
    while row < K {
        let a_row = sample_poly(seed, idx);
        idx += 1;
        let a_row_ntt = ntt_inplace(a_row);
        a_ntt.append(a_row_ntt);
        row += 1;
    }

    let mut k: usize = 0;
    while k < K {
        let s = sample_poly(seed, idx);
        idx += 1;
        let e = sample_poly(seed, idx);
        idx += 1;

        let s_ntt_k = ntt_inplace(s);
        let mut acc_array: Array<u16> = array![];
        let mut zi: usize = 0;
        while zi < N {
            acc_array.append(0_u16);
            zi += 1;
        }
        let mut acc = acc_array.span();
        let mut a_iter = a_ntt.span();
        while let Some(a_col) = a_iter.pop_front() {
            let prod = pointwise_mul(*a_col, s_ntt_k);
            let prod_intt = intt_inplace(prod);
            acc = add(acc, prod_intt);
        }
        let t_poly = add(acc, e);
        let t_ntt_k = ntt_inplace(t_poly);

        s_ntt.append(s_ntt_k);
        t_ntt.append(t_ntt_k);
        k += 1;
    }

    (PublicKey { a_ntt, t_ntt }, SecretKey { s_ntt })
}

/// Encapsulate using a peer's public key and a seed-derived message.
pub fn encapsulate(pk: PublicKey, seed: u64) -> (Ciphertext, SharedSecret) {
    let mut idx: u16 = 101; // different domain separators
    let mut r_ntt_vec: Array<Poly> = array![];
    let mut e1_vec: Array<Poly> = array![];

    // Sample r and e1
    let mut i: usize = 0;
    while i < K {
        let r = ntt_inplace(sample_poly(seed, idx));
        idx += 1;
        let e1 = sample_poly(seed, idx);
        idx += 1;
        r_ntt_vec.append(r);
        e1_vec.append(e1);
        i += 1;
    }
    let e2 = sample_poly(seed, idx);
    idx += 1;

    // Expand seed into 32 bytes.
    let mut msg_bytes: Array<u8> = array![];
    let mut tmp_seed = seed;
    let mut shift: usize = 0;
    while shift < 8 {
        msg_bytes.append((tmp_seed % 256_u64).try_into().unwrap());
        tmp_seed = tmp_seed / 256_u64;
        shift += 1;
    }
    while msg_bytes.len() < 32 {
        msg_bytes.append(0_u8);
    }
    let m_poly = encode_message(msg_bytes.span());

    // u = A * r + e1
    let mut u_vec: Array<Poly> = array![];
    let mut row: usize = 0;
    let mut r_rows = r_ntt_vec.span();
    let mut e1_rows = e1_vec.span();
    while row < K {
        let mut acc_array: Array<u16> = array![];
        let mut zi: usize = 0;
        while zi < N {
            acc_array.append(0_u16);
            zi += 1;
        }
        let mut acc = acc_array.span();
        let r_row = *r_rows.pop_front().unwrap();
        let mut a_iter = pk.a_ntt.span();
        while let Some(a_col) = a_iter.pop_front() {
            let prod = pointwise_mul(*a_col, r_row);
            let prod_intt = intt_inplace(prod);
            acc = add(acc, prod_intt);
        }
        let u_row = add(acc, *e1_rows.pop_front().unwrap());
        u_vec.append(u_row);
        row += 1;
    }

    // v = t * r + e2 + m
    let mut acc_array: Array<u16> = array![];
    let mut zi: usize = 0;
    while zi < N {
        acc_array.append(0_u16);
        zi += 1;
    }
    let mut acc = acc_array.span();
    let mut t_iter = pk.t_ntt.span();
    let mut r_iter = r_ntt_vec.span();
    while let (Some(t_col), Some(r_col)) = (t_iter.pop_front(), r_iter.pop_front()) {
        let prod = pointwise_mul(*t_col, *r_col);
        let prod_intt = intt_inplace(prod);
        acc = add(acc, prod_intt);
    }
    let v = add(add(acc, e2), m_poly);

    let ss = derive_secret(v);
    (Ciphertext { u: u_vec, v }, ss)
}

/// Decapsulate a ciphertext.
pub fn decapsulate(sk: SecretKey, ct: Ciphertext) -> SharedSecret {
    // Compute t = v - <u, s>
    let mut acc = ct.v;
    let mut u_iter = ct.u.span();
    let mut s_iter = sk.s_ntt.span();
    while let (Some(u_row), Some(s_row)) = (u_iter.pop_front(), s_iter.pop_front()) {
        let prod = pointwise_mul(ntt_inplace(*u_row), *s_row);
        let prod_intt = intt_inplace(prod);
        acc = sub(acc, prod_intt);
    }
    derive_secret(acc)
}

/// Lightweight hash/PRF over a polynomial to derive a 32-byte shared secret.
fn derive_secret(poly: Poly) -> SharedSecret {
    let mut acc: u32 = 0;
    for c in poly {
        acc = (acc + ((*c).into())) % 0xFFFF_FFFF_u32;
        acc = (acc * 1664525_u32 + 1013904223_u32) % 0xFFFF_FFFF_u32;
    }

    let mut out: Array<u8> = array![];
    let mut i: usize = 0;
    while i < 32 {
        let i_u32: u32 = i.try_into().unwrap();
        acc = (acc + 0x9E37_79B1_u32 + i_u32) % 0xFFFF_FFFF_u32;
        acc = (acc * 1103515245_u32 + 12345_u32) % 0xFFFF_FFFF_u32;
        out.append((acc % 256_u32).try_into().unwrap());
        i += 1;
    }
    SharedSecret { bytes: out }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_shared_secret() {
        let seed: u64 = 0x1122_3344_5566_7788;
        let (pk, sk) = keygen(seed);
        let (ct, ss_enc) = encapsulate(pk, seed + 0xA5A5_A5A5_5A5A_5A5A);
        let ss_dec = decapsulate(sk, ct);
        assert_eq!(ss_enc.bytes, ss_dec.bytes);
    }
}

