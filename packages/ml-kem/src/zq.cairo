// SPDX-License-Identifier: MIT

//! Arithmetic modulo Q for ML-KEM (Kyber-lite).

use core::num::traits::CheckedAdd;
use crate::params::{Q, Q32, Q64};

/// Add two values modulo Q.
pub fn add_mod(a: u16, b: u16) -> u16 {
    a.checked_add(b).expect('u16 add overflow') % Q
}

/// Subtract two values modulo Q.
pub fn sub_mod(a: u16, b: u16) -> u16 {
    (a.checked_add(Q).expect('u16 + Q overflow') - b) % Q
}

/// Multiply two values modulo Q.
pub fn mul_mod(a: u16, b: u16) -> u16 {
    let aa: u32 = a.into();
    let bb: u32 = b.into();
    let res = (aa * bb) % Q32;
    res.try_into().unwrap()
}

/// Multiply three values modulo Q.
pub fn mul3_mod(a: u16, b: u16, c: u16) -> u16 {
    let aa: u64 = a.into();
    let bb: u64 = b.into();
    let cc: u64 = c.into();
    let res = (aa * bb * cc) % Q64;
    res.try_into().unwrap()
}

