// SPDX-License-Identifier: MIT

//! Polynomial helpers for ML-KEM.

use crate::ntt::{intt, mul_ntt, ntt};
use crate::params::N;
use crate::zq::{add_mod, sub_mod};

pub type Poly = Span<u16>;

pub fn add(mut a: Poly, mut b: Poly) -> Poly {
    assert(a.len() == b.len(), 'poly length mismatch');
    let mut r = array![];
    while let Some(x) = a.pop_front() {
        let y = b.pop_front().unwrap();
        r.append(add_mod(*x, *y));
    }
    r.span()
}

pub fn sub(mut a: Poly, mut b: Poly) -> Poly {
    assert(a.len() == b.len(), 'poly length mismatch');
    let mut r = array![];
    while let Some(x) = a.pop_front() {
        let y = b.pop_front().unwrap();
        r.append(sub_mod(*x, *y));
    }
    r.span()
}

pub fn pointwise_mul(mut a: Poly, mut b: Poly) -> Poly {
    mul_ntt(a, b)
}

pub fn ntt_inplace(p: Poly) -> Poly {
    ntt(p)
}

pub fn intt_inplace(p: Poly) -> Poly {
    intt(p)
}

/// Encode a short message as a polynomial with small coefficients (0 or 1).
pub fn encode_message(msg: Span<u8>) -> Poly {
    let mut coeffs: Array<u16> = array![];
    for byte in msg {
        let mut bit_idx: u8 = 0;
        while bit_idx < 8 {
            if coeffs.len() >= N {
                break;
            }
            let mut pow: u8 = 1;
            let mut s: u8 = 0;
            while s < bit_idx {
                pow = pow * 2_u8;
                s += 1;
            }
            let bit: u16 = ((*byte / pow) % 2_u8).into();
            coeffs.append(bit);
            bit_idx += 1;
        }
    }
    while coeffs.len() < N {
        coeffs.append(0_u16);
    }
    coeffs.span()
}

