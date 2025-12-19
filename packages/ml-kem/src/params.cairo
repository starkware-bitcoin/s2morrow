// SPDX-License-Identifier: MIT

//! ML-KEM (Kyber-lite) parameters

pub const N: usize = 256;
pub const Q: u16 = 3329;
pub const Q32: u32 = 3329;
pub const Q64: u64 = 3329;

/// Kyber512-like dimension for this simplified envelope encryption flow.
pub const K: usize = 2;

/// Scaling factor used in the inverse NTT (2^{-8} mod q).
pub const INV_N: u16 = 3327; // 256^{-1} mod 3329

