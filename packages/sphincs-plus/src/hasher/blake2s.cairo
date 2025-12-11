// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

use core::blake::{blake2s_compress, blake2s_finalize};
use core::box::BoxImpl;

const BLAKE2S_256_IV: [u32; 8] = [
    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Blake2s incremental state.
#[derive(Debug, Drop, Copy)]
pub struct HashState {
    pub(crate) h: Box<[u32; 8]>,
    pub(crate) byte_len: u32,
}

impl HashStateDefault of Default<HashState> {
    fn default() -> HashState {
        HashState { h: BoxImpl::new([0; 8]), byte_len: 0 }
    }
}

/// Initializes the Blake2s hasher state with IV and resets the byte length.
pub fn hash_init(ref state: HashState) {
    state.h = BoxImpl::new(BLAKE2S_256_IV);
    state.byte_len = 0;
}

pub fn hash_update_block(ref state: HashState, data: [u32; 16]) {
    state.byte_len += 64;
    state.h = blake2s_compress(state.h, state.byte_len, BoxImpl::new(data));
}

pub fn hash_finalize_block(ref state: HashState, data: [u32; 16]) -> [u32; 8] {
    blake2s_finalize(state.h, state.byte_len + 64, BoxImpl::new(data)).unbox()
}

/// Updates the Blake2s hasher state with the given data (data length must be a multiple of 16).
pub fn hash_update(ref state: HashState, mut data: Span<u32>) {
    while let Some(chunk) = data.multi_pop_front::<16>() {
        state.byte_len += 64;
        blake2s_compress(state.h, state.byte_len, *chunk);
    }
    assert(data.is_empty(), 'unaligned blake2s block');
}

/// Finalizes the Blake2s hasher state and returns the hash.
pub fn hash_finalize(
    mut state: HashState, input: Array<u32>, last_input_word: u32, last_input_num_bytes: u32,
) -> [u32; 8] {
    let mut data = input.span();

    while let Some(chunk) = data.multi_pop_front::<16>() {
        state.byte_len += 64;
        blake2s_compress(state.h, state.byte_len, *chunk);
    }

    let mut buffer: Array<u32> = array![];
    buffer.append_span(data);

    if last_input_num_bytes == 1 {
        buffer.append(last_input_word * 0x1000000);
    } else if last_input_num_bytes == 2 {
        buffer.append(last_input_word * 0x10000);
    } else if last_input_num_bytes == 3 {
        buffer.append(last_input_word * 0x100);
    }

    state.byte_len += buffer.len() * 4;

    for _ in buffer.len()..16 {
        buffer.append(0);
    }

    let msg = buffer.span().try_into().expect('Cast to @Blake2sInput failed');
    let res = blake2s_finalize(state.h, state.byte_len, *msg);
    res.unbox()
}
