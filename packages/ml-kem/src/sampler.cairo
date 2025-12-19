// SPDX-License-Identifier: MIT

//! Deterministic sampler used for tests and reproducible vectors.

use crate::params::{N, Q};

/// Simple 64-bit xorshift to derive pseudo-random u16 values < Q from a seed and nonce.
pub fn sample_poly(seed: u64, nonce: u16) -> Span<u16> {
    let upper: u32 = (seed / 0x1_0000_0000_u64).try_into().unwrap();
    let seed_low: u32 = seed.try_into().unwrap();
    let nonce_u32: u32 = nonce.try_into().unwrap();
    let mut state: u32 = (seed_low + upper + nonce_u32 + 0xA5A5_1234_u32) % 0xFFFF_FFFF_u32;
    let mut out: Array<u16> = array![];
    let modulus: u32 = Q.into();

    let mut i: usize = 0;
    while i < N {
        state = (state * 1664525_u32 + 1013904223_u32) % 0xFFFF_FFFF_u32;
        out.append((state % modulus).try_into().unwrap());
        i += 1;
    }

    out.span()
}

