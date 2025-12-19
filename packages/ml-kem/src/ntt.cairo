// SPDX-License-Identifier: MIT

//! Iterative Cooley–Tukey NTT for Kyber-style polynomials (n = 256, q = 3329).

use crate::ntt_constants::ZETAS;
use crate::params::{INV_N, N, Q};
use crate::zq::{add_mod, mul_mod, sub_mod};

/// Forward NTT. Uses fresh arrays per stage to avoid in-place mutation.
pub fn ntt(poly: Span<u16>) -> Span<u16> {
    assert(poly.len() == N, 'invalid poly length');
    let mut data = poly;
    let mut zetas = ZETAS.span();

    let mut len: usize = N / 2;
    while len >= 1 {
        let mut out = array![];
        let mut data_iter = data;
        while data_iter.len() > 0 {
            let zeta = *zetas.pop_front().unwrap();
            let mut j: usize = 0;
            while j < len {
                let u = *data_iter.pop_front().unwrap();
                let v = *data_iter.pop_front().unwrap();
                let t = mul_mod(zeta, v);
                out.append(add_mod(u, t));
                out.append(sub_mod(u, t));
                j += 1;
            }
        }
        data = out.span();
        len /= 2;
    }

    data
}

/// Inverse NTT followed by scaling by N^{-1}.
pub fn intt(poly: Span<u16>) -> Span<u16> {
    assert(poly.len() == N, 'invalid poly length');
    let mut data = poly;
    let mut inv_zetas = crate::ntt_constants::INV_ZETAS.span();

    let mut len: usize = 1;
    while len < N {
        let mut out = array![];
        let mut data_iter = data;
        while data_iter.len() > 0 {
            let zeta = *inv_zetas.pop_front().unwrap();
            let mut j: usize = 0;
            while j < len {
                let u = *data_iter.pop_front().unwrap();
                let v = *data_iter.pop_front().unwrap();
                out.append(add_mod(u, v));
                let t = sub_mod(u, v);
                out.append(mul_mod(zeta, t));
                j += 1;
            }
        }
        data = out.span();
        len *= 2;
    }

    let mut scaled = array![];
    while let Some(c) = data.pop_front() {
        scaled.append(mul_mod(*c, INV_N));
    }
    scaled.span()
}

/// Point-wise multiplication in the NTT domain.
pub fn mul_ntt(mut a_ntt: Span<u16>, mut b_ntt: Span<u16>) -> Span<u16> {
    assert(a_ntt.len() == b_ntt.len(), 'length mismatch');
    let mut res = array![];
    while let Some(a) = a_ntt.pop_front() {
        let b = b_ntt.pop_front().unwrap();
        res.append(mul_mod(*a, *b));
    }
    res.span()
}

/// Convenience helper: c = intt(ntt(a) * ntt(b))
pub fn mul_poly(a: Span<u16>, b: Span<u16>) -> Span<u16> {
    let a_ntt = ntt(a);
    let b_ntt = ntt(b);
    let c_ntt = mul_ntt(a_ntt, b_ntt);
    intt(c_ntt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut input = array![];
        let mut i: u16 = 0;
        while i < N.try_into().unwrap() {
            input.append(i % Q);
            i += 1;
        }
        let f = input.span();
        let back = intt(ntt(f));
        assert_eq!(f, back);
    }
}

