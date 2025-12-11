// SPDX-FileCopyrightText: 2025 StarkWare Industries <contact@starkware.co>
//
// SPDX-License-Identifier: Apache-2.0

use core::integer::u32_safe_divmod;
use core::num::traits::{OverflowingAdd, OverflowingMul};

/// 8-element tuple of u32.
type T8 = (u32, u32, u32, u32, u32, u32, u32, u32);

/// State of the SHA-256 hasher.
#[derive(Debug, Drop, Copy, Default)]
pub struct HashState {
    pub(crate) h: T8,
    pub(crate) byte_len: u32,
}

/// Initializes the SHA-256 hasher state with IV and resets the byte length.
pub fn hash_init(ref state: HashState) {
    state.h = h;
    state.byte_len = 0;
}

/// Updates the SHA-256 hasher state with the given data (data length must be a multiple of 16).
pub fn hash_update(ref state: HashState, mut data: Span<u32>) {
    let data_len = data.len();
    while let Some(chunk) = data.multi_pop_front::<16>() {
        state.h = sha256_inner(chunk.span(), state.h);
    }
    assert(data.is_empty(), 'unaligned sha256 block');
    state.byte_len += data_len * 4;
}

/// Updates the SHA-256 hasher state with the given data (data length must be a multiple of 16).
pub fn hash_update_block(ref state: HashState, data: [u32; 16]) {
    state.byte_len += 64;
    state.h = sha256_inner(data.span(), state.h);
}

/// Finalizes the SHA-256 hasher state and returns the hash.
///
/// Adds padding to the input array for SHA-256. The padding is defined as follows:
/// 1. Append a single bit with value 1 to the end of the array.
/// 2. Append zeros until the length of the array is 448 mod 512.
/// 3. Append the length of the array in bits as a 64-bit number.
///
/// Use last_input_word when the number of bytes in the last input word is less than 4.
pub fn hash_finalize(
    mut state: HashState, mut input: Array<u32>, last_input_word: u32, last_input_num_bytes: u32,
) -> [u32; 8] {
    state.byte_len += input.len() * 4 + last_input_num_bytes;

    if last_input_num_bytes == 0 {
        input.append(0x80000000);
    } else {
        let (q, m, pad) = if last_input_num_bytes == 1 {
            (0x100, 0x1000000, 0x800000)
        } else if last_input_num_bytes == 2 {
            (0x10000, 0x10000, 0x8000)
        } else {
            (0x1000000, 0x100, 0x80)
        };
        let (_, r) = u32_safe_divmod(last_input_word, q);
        input.append(r * m + pad);
    }

    let remaining = 16 - ((input.len() + 1) % 16);
    append_zeros(ref input, remaining);

    // NOTE: bit length up to 2^32-1 (low 32 bits), we set high 32 bits to 0 on the previous step.
    // This is a concious optimization.
    input.append(state.byte_len * 8);

    let mut data = input.span();
    while let Some(chunk) = data.multi_pop_front::<16>() {
        state.h = sha256_inner(chunk.span(), state.h);
    }

    assert(data.is_empty(), 'unaligned sha256 block');

    let (d0, d1, d2, d3, d4, d5, d6, d7) = state.h;
    [d0, d1, d2, d3, d4, d5, d6, d7]
}

/// Appends `count` zeros to the array.
fn append_zeros(ref arr: Array<u32>, count: u32) {
    if count == 0 {
        return;
    }
    arr.append(0);
    if count == 1 {
        return;
    }
    arr.append(0);
    if count == 2 {
        return;
    }
    arr.append(0);
    if count == 3 {
        return;
    }
    arr.append(0);
    if count == 4 {
        return;
    }
    arr.append(0);
    if count == 5 {
        return;
    }
    arr.append(0);
    if count == 6 {
        return;
    }
    arr.append(0);
    if count == 7 {
        return;
    }
    arr.append(0);
    if count == 8 {
        return;
    }
    arr.append(0);
    if count == 9 {
        return;
    }
    arr.append(0);
    if count == 10 {
        return;
    }
    arr.append(0);
    if count == 11 {
        return;
    }
    arr.append(0);
    if count == 12 {
        return;
    }
    arr.append(0);
    if count == 13 {
        return;
    }
    arr.append(0);
    if count == 14 {
        return;
    }
    arr.append(0);
    if count == 15 {
        return;
    }
    arr.append(0);
}

fn sha256_inner(data: Span<u32>, h: T8) -> T8 {
    let mut w = create_message_schedule(data);
    let mut g = h;
    let mut k = k.span();

    while let Some(ki) = k.pop_front() {
        let wi = w.pop_front().unwrap();
        g = compression(*wi, *ki, g);
    }

    let (h0, h1, h2, h3, h4, h5, h6, h7) = h;
    let (g0, g1, g2, g3, g4, g5, g6, g7) = g;

    let (t0, _) = h0.overflowing_add(g0);
    let (t1, _) = h1.overflowing_add(g1);
    let (t2, _) = h2.overflowing_add(g2);
    let (t3, _) = h3.overflowing_add(g3);
    let (t4, _) = h4.overflowing_add(g4);
    let (t5, _) = h5.overflowing_add(g5);
    let (t6, _) = h6.overflowing_add(g6);
    let (t7, _) = h7.overflowing_add(g7);
    (t0, t1, t2, t3, t4, t5, t6, t7)
}

fn compression(wi: u32, ki: u32, h: T8) -> T8 {
    let (h0, h1, h2, h3, h4, h5, h6, h7) = h;
    let s1 = bsig1(h4);
    let ch = ch(h4, h5, h6);
    let (tmp, _) = h7.overflowing_add(s1);
    let (tmp, _) = tmp.overflowing_add(ch);
    let (tmp, _) = tmp.overflowing_add(ki);
    let (temp1, _) = tmp.overflowing_add(wi);
    let s0 = bsig0(h0);
    let maj = maj(h0, h1, h2);
    let (temp2, _) = s0.overflowing_add(maj);
    let (temp3, _) = temp1.overflowing_add(temp2);
    let t0 = temp3;
    let (temp3, _) = h3.overflowing_add(temp1);
    let t4 = temp3;
    (t0, h0, h1, h2, t4, h4, h5, h6)
}

fn create_message_schedule(data: Span<u32>) -> Span<u32> {
    let mut result: Array<u32> = data.into();
    for i in 16..64_usize {
        let s0 = ssig0(*result[i - 15]);
        let s1 = ssig1(*result[i - 2]);
        let (tmp, _) = (*result[i - 16]).overflowing_add(s0);
        let (tmp, _) = tmp.overflowing_add(*result[i - 7]);
        let (res, _) = tmp.overflowing_add(s1);
        result.append(res);
    }
    result.span()
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((x ^ 0xffffffff) & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn bsig0(x: u32) -> u32 {
    let (rhs, _) = x.overflowing_mul(0x40000000);
    let x1 = (x / 0x4) | (rhs);
    let (rhs, _) = x.overflowing_mul(0x80000);
    let x2 = (x / 0x2000) | rhs;
    let (rhs, _) = x.overflowing_mul(0x400);
    let x3 = (x / 0x400000) | rhs;
    x1 ^ x2 ^ x3
}

fn bsig1(x: u32) -> u32 {
    let (rhs, _) = x.overflowing_mul(0x4000000);
    let x1 = (x / 0x40) | rhs;
    let (rhs, _) = x.overflowing_mul(0x200000);
    let x2 = (x / 0x800) | rhs;
    let (rhs, _) = x.overflowing_mul(0x80);
    let x3 = (x / 0x2000000) | rhs;
    x1 ^ x2 ^ x3
}

fn ssig0(x: u32) -> u32 {
    let (rhs, _) = x.overflowing_mul(0x2000000);
    let x1 = (x / 0x80) | rhs;
    let (rhs, _) = x.overflowing_mul(0x4000);
    let x2 = (x / 0x40000) | rhs;
    let x3 = (x / 0x8);
    x1 ^ x2 ^ x3
}

fn ssig1(x: u32) -> u32 {
    let (rhs, _) = x.overflowing_mul(0x8000);
    let x1 = (x / 0x20000) | rhs;
    let (rhs, _) = x.overflowing_mul(0x2000);
    let x2 = (x / 0x80000) | rhs;
    let x3 = (x / 0x400);
    x1 ^ x2 ^ x3
}

/// Sha256 IV.
const h: T8 = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
);

/// Sha256 round constants.
const k: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[cfg(test)]
mod tests {
    use crate::word_array::WordArrayTrait;
    use crate::word_array::hex::words_from_hex;
    use super::*;

    #[test]
    fn test_sha256_finalize() {
        let buf = words_from_hex(
            "002e82f752b663241e060000000100000000000000047c9935a0b07694aa0c6d10e4db6b1add",
        );
        let mut state = HashState {
            h: (
                0x14163465,
                0x04164476,
                0xf4c272a1,
                0xd0f2cd7e,
                0xdf396a8b,
                0x47ffef37,
                0x41fe0476,
                0xaa25036a,
            ),
            byte_len: 64,
        };
        let expected = [
            0x9729f44d, 0x1c003350, 0x14a674be, 0xd98b2569, 0x15372d1c, 0x28e8a776, 0x3d1cded7,
            0xd69a1852,
        ];

        let (input, last_input_word, last_input_num_bytes) = buf.into_components();

        let res = hash_finalize(state, input, last_input_word, last_input_num_bytes);
        assert_eq!(res, expected);
    }
}
