/// Blake2s implementation for SPHINCS+ with Cairo compatibility.
///
/// This implements Blake2s compression/finalization directly to match Cairo's interface,
/// which allows starting from arbitrary h states (not just IV).
///
/// Cairo's blake2s_compress(h, byte_len, msg) and blake2s_finalize(h, byte_len, msg)
/// take an explicit h state, allowing pre-computed states to be reused.

use crate::context::SpxCtx;

/// Blake2s block size in bytes
pub const SPX_BLAKE2S_BLOCK_BYTES: usize = 64;
/// Blake2s output size in bytes
pub const SPX_BLAKE2S_OUTPUT_BYTES: usize = 32;
/// Address bytes for Blake2s (full 32 bytes for sparse address)
pub const SPX_BLAKE2S_ADDR_BYTES: usize = 32;

/// Blake2s state for incremental hashing
pub const BLAKE2S_STATE_BYTES: usize = 40;

/// Blake2s-256 IV (with parameter block XOR for 32-byte output, no key)
/// h[0] = 0x6A09E667 ^ 0x01010020 = 0x6B08E647
pub const BLAKE2S_256_IV: [u32; 8] = [
    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Blake2s sigma permutations
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Blake2s mixing function G
#[inline]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// Blake2s compression function
/// h: current state (8 u32 words)
/// m: message block (16 u32 words)
/// t: byte count (total bytes hashed including this block)
/// f: finalization flag (true for last block)
fn blake2s_compress(h: &[u32; 8], m: &[u32; 16], t: u64, f: bool) -> [u32; 8] {
    // Standard Blake2s IV (not modified with param block)
    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..16].copy_from_slice(&IV);

    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    if f {
        v[14] = !v[14];
    }

    for i in 0..10 {
        let s = &SIGMA[i];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    let mut result = [0u32; 8];
    for i in 0..8 {
        result[i] = h[i] ^ v[i] ^ v[i + 8];
    }
    result
}

/// Cairo-compatible Blake2s state
/// Stores h state (8 u32 words) and byte_len (u32)
/// Total: 36 bytes but we use 40 for alignment
#[derive(Clone, Copy)]
pub struct Blake2sState {
    pub h: [u32; 8],
    pub byte_len: u32,
}

impl Default for Blake2sState {
    fn default() -> Self {
        Self {
            h: [0; 8],  // Cairo Default::default() uses zeros, NOT IV
            byte_len: 0,
        }
    }
}

impl Blake2sState {
    /// Create a new state initialized with Blake2s IV
    pub fn new() -> Self {
        Self {
            h: BLAKE2S_256_IV,
            byte_len: 0,
        }
    }

    /// Create from raw state (for continuing from pre-computed state)
    pub fn from_state(h: [u32; 8], byte_len: u32) -> Self {
        Self { h, byte_len }
    }

    /// Update state with a full 64-byte block (16 u32 words)
    /// This matches Cairo's hash_update_block
    pub fn update_block(&mut self, block: &[u32; 16]) {
        self.byte_len += 64;
        self.h = blake2s_compress(&self.h, block, self.byte_len as u64, false);
    }

    /// Finalize with a block (may be partial, zero-padded)
    /// This matches Cairo's hash_finalize_block
    pub fn finalize_block(&mut self, block: &[u32; 16]) -> [u32; 8] {
        let final_byte_len = self.byte_len + 64;
        blake2s_compress(&self.h, block, final_byte_len as u64, true)
    }
}

/// Cairo-compatible Blake2s hasher state (high-level wrapper)
pub struct CairoBlake2sState {
    state: Blake2sState,
    buffer: Vec<u8>,
}

impl CairoBlake2sState {
    pub fn new() -> Self {
        Self {
            state: Blake2sState::new(),
            buffer: Vec::new(),
        }
    }

    /// Create from pre-computed state (for use with ctx.state_seeded)
    pub fn from_state(h: [u32; 8], byte_len: u32) -> Self {
        Self {
            state: Blake2sState::from_state(h, byte_len),
            buffer: Vec::new(),
        }
    }

    /// Update hasher with data (bytes, LE format)
    /// Note: We only process complete blocks if there's MORE data coming after.
    /// The last block (even if 64 bytes) must be finalized, not updated.
    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);

        // Process complete blocks, but ONLY if there's data after them
        // Keep at least 1 byte in buffer to ensure the last block goes through finalize
        while self.buffer.len() > 64 {
            let mut block = [0u32; 16];
            for i in 0..16 {
                block[i] = u32::from_le_bytes(self.buffer[i*4..i*4+4].try_into().unwrap());
            }
            self.state.update_block(&block);
            self.buffer.drain(..64);
        }
    }

    /// Finalize and get the hash
    pub fn finalize(self, out: &mut [u8]) {
        // Convert buffer to u32 words
        let mut final_block = [0u32; 16];
        for i in 0..self.buffer.len() / 4 {
            final_block[i] = u32::from_le_bytes(self.buffer[i*4..i*4+4].try_into().unwrap());
        }
        // Handle partial last word
        let remainder = self.buffer.len() % 4;
        if remainder > 0 {
            let word_idx = self.buffer.len() / 4;
            let mut word_bytes = [0u8; 4];
            word_bytes[..remainder].copy_from_slice(&self.buffer[word_idx*4..]);
            final_block[word_idx] = u32::from_le_bytes(word_bytes);
        }

        // Total bytes = previously processed + current buffer
        let final_byte_len = self.state.byte_len + self.buffer.len() as u32;

        let result = blake2s_compress(&self.state.h, &final_block, final_byte_len as u64, true);

        for i in 0..8 {
            out[i*4..i*4+4].copy_from_slice(&result[i].to_le_bytes());
        }
    }
}

/// Initialize Blake2s incremental state
pub fn blake2s_inc_init(state: &mut [u8]) {
    state.fill(0);
}

/// One-shot Blake2s hash with Cairo compatibility
pub fn blake2s(out: &mut [u8], input: &[u8], inlen: usize) {
    let mut hasher = CairoBlake2sState::new();
    hasher.update(&input[..inlen]);
    hasher.finalize(out);
}

/// Absorb the constant pub_seed using one round of the compression function
/// This initializes state_seeded_blake, which can then be reused in thash
///
/// Matches Cairo's initialize_hash_function:
/// 1. Initialize state with Blake2s IV (with param block XOR)
/// 2. Compress with: [pk_seed(4 words), zeros(12 words)] = 64 bytes
pub fn seed_state(ctx: &mut SpxCtx) {
    // Build the seed block: [pub_seed(4 words), zeros(12 words)]
    let mut block = [0u32; 16];
    for i in 0..4 {
        block[i] = u32::from_le_bytes(ctx.pub_seed[i*4..i*4+4].try_into().unwrap());
    }

    // Initialize state and compress the seed block
    let mut state = Blake2sState::new();  // Starts with IV
    state.update_block(&block);

    // Store the resulting state in ctx.state_seeded_blake
    // Format: [h[0..8] as LE bytes (32 bytes)] + [byte_len as LE u64 (8 bytes)]
    for i in 0..8 {
        ctx.state_seeded_blake[i*4..i*4+4].copy_from_slice(&state.h[i].to_le_bytes());
    }
    ctx.state_seeded_blake[32..40].copy_from_slice(&(state.byte_len as u64).to_le_bytes());
}

/// Load Blake2sState from ctx.state_seeded_blake
pub fn load_seeded_state(ctx: &SpxCtx) -> Blake2sState {
    let mut h = [0u32; 8];
    for i in 0..8 {
        h[i] = u32::from_le_bytes(ctx.state_seeded_blake[i*4..i*4+4].try_into().unwrap());
    }
    let byte_len = u64::from_le_bytes(ctx.state_seeded_blake[32..40].try_into().unwrap()) as u32;
    Blake2sState::from_state(h, byte_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2s_cairo_empty() {
        // Test against known Cairo blake2s output for empty input
        // From stark_blake.rs: hash([]) = 0x307a216994809079d02111e17c4a354248b6551f1ea5a12cfd0d251bf9eed01e
        let mut out = [0u8; 32];
        blake2s(&mut out, &[], 0);

        // Convert to u32 words using LE and display as hex
        let mut words = Vec::new();
        for i in 0..8 {
            let word = u32::from_le_bytes(out[i*4..i*4+4].try_into().unwrap());
            words.push(format!("{:08x}", word));
        }
        let hex_str = words.join("");
        assert_eq!(hex_str, "307a216994809079d02111e17c4a354248b6551f1ea5a12cfd0d251bf9eed01e");
    }

    #[test]
    fn test_blake2s_cairo_zeros() {
        // Test against known Cairo blake2s output for 32 zero bytes
        // From stark_blake.rs: hash([0x00...00]) = 0xa95e0b32c23b659e41db93b54e0ad1304c0b3afd67a6e1c2718d672bad33bddf
        let input = [0u8; 32];
        let mut out = [0u8; 32];
        blake2s(&mut out, &input, 32);

        let mut words = Vec::new();
        for i in 0..8 {
            let word = u32::from_le_bytes(out[i*4..i*4+4].try_into().unwrap());
            words.push(format!("{:08x}", word));
        }
        let hex_str = words.join("");
        assert_eq!(hex_str, "a95e0b32c23b659e41db93b54e0ad1304c0b3afd67a6e1c2718d672bad33bddf");
    }

    #[test]
    fn test_blake2s_cairo_pair() {
        // Test against stark_blake test_blake2s_hasher_pair:
        // hash(["0xc713e33d89122b85e2f646cc518c2e6ef88b06d3b016104faa95f84f878dab66",
        //       "0xc713e33d89122b85e2f646cc518c2e6ef88b06d3b016104faa95f84f878dab66"])
        // = 0x693aa1ab81c6362fe339fc4c7f6d8ddb1e515701e58c5bb2fb54a193c8287fdc

        // The hex input represents u32 words. Need to convert to bytes for our hasher.
        // stark_blake: takes hex, converts to BE bytes, then reverses within each word
        // Our approach: we expect LE bytes directly (matching how Cairo works)

        // The input "0xc713e33d89122b85e2f646cc518c2e6ef88b06d3b016104faa95f84f878dab66" is 64 hex chars = 32 bytes
        // As u32 words: [0xc713e33d, 0x89122b85, 0xe2f646cc, 0x518c2e6e, 0xf88b06d3, 0xb016104f, 0xaa95f84f, 0x878dab66]

        // In stark_blake, these words are converted to BE bytes then reversed:
        // 0xc713e33d as BE: [0xc7, 0x13, 0xe3, 0x3d]
        // After reversal: [0x3d, 0xe3, 0x13, 0xc7]
        // blake2 interprets as LE: 0xc713e33d ✓

        // So for our hasher, we need to provide LE bytes:
        let words1: [u32; 8] = [0xc713e33d, 0x89122b85, 0xe2f646cc, 0x518c2e6e, 0xf88b06d3, 0xb016104f, 0xaa95f84f, 0x878dab66];

        let mut input = [0u8; 64];
        for i in 0..8 {
            input[i*4..i*4+4].copy_from_slice(&words1[i].to_le_bytes());
        }
        for i in 0..8 {
            input[32 + i*4..32 + i*4+4].copy_from_slice(&words1[i].to_le_bytes());
        }

        let mut out = [0u8; 32];
        blake2s(&mut out, &input, 64);

        let mut words = Vec::new();
        for i in 0..8 {
            let word = u32::from_le_bytes(out[i*4..i*4+4].try_into().unwrap());
            words.push(format!("{:08x}", word));
        }
        let hex_str = words.join("");
        assert_eq!(hex_str, "693aa1ab81c6362fe339fc4c7f6d8ddb1e515701e58c5bb2fb54a193c8287fdc");
    }
}
