#![allow(non_snake_case)]
use crate::context::SpxCtx;
use crate::utils::*;
use crate::params::*;
use crate::blake2s::*;

/// Initialize the hash function (no-op for Blake2s, seed_state is called separately)
pub fn initialize_hash_function(ctx: &mut SpxCtx) {
    seed_state(ctx);
}

/// Computes PRF(pk_seed, sk_seed, addr) using Cairo-compatible Blake2s.
/// Uses sparse address format (8 u32 words as little-endian bytes).
///
/// Cairo uses a two-block structure:
///   Block 1 (seed): [pub_seed(16 bytes), zeros(48 bytes)]
///   Block 2 (finalize): [addr(32 bytes), sk_seed(16 bytes), zeros(16 bytes)]
pub fn prf_addr(out: &mut [u8], ctx: &SpxCtx, addr: &mut [u32]) {
    let mut hasher = CairoBlake2sState::new();

    // Block 1: [pub_seed(16 bytes), zeros(48 bytes)] = 64 bytes
    let mut block1 = [0u8; 64];
    block1[..SPX_N].copy_from_slice(&ctx.pub_seed);
    hasher.update(&block1);

    // Block 2: [addr(32 bytes), sk_seed(16 bytes), zeros(16 bytes)] = 64 bytes
    let mut block2 = [0u8; 64];

    #[cfg(feature = "sparse_addr")]
    {
        let addr_bytes = sparse_address_to_bytes(addr);
        block2[..32].copy_from_slice(&addr_bytes);
    }
    #[cfg(not(feature = "sparse_addr"))]
    {
        let addr_bytes = address_to_bytes(addr);
        block2[..32].copy_from_slice(&addr_bytes);
    }

    block2[32..32 + SPX_N].copy_from_slice(&ctx.sk_seed);
    // zeros at [48..64] already set

    hasher.update(&block2);

    let mut outbuf = [0u8; SPX_BLAKE2S_OUTPUT_BYTES];
    hasher.finalize(&mut outbuf);
    out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}

/// Computes the message-dependent randomness R, using a secret seed as a key
/// for HMAC-Blake2s, and an optional randomization value prefixed to the message.
pub fn gen_message_random(
    r: &mut [u8],
    sk_prf: &[u8],
    optrand: &[u8],
    m: &[u8],
    mlen: usize,
    _ctx: &SpxCtx,
) {
    // HMAC-Blake2s: H((K ^ opad) || H((K ^ ipad) || message))
    // where K is sk_prf, padded to block size

    let mut buf = [0u8; SPX_BLAKE2S_BLOCK_BYTES + SPX_BLAKE2S_OUTPUT_BYTES];

    // Inner hash: H((K ^ ipad) || optrand || message)
    let mut inner_hasher = CairoBlake2sState::new();

    // K ^ ipad (0x36)
    for i in 0..SPX_N {
        buf[i] = 0x36 ^ sk_prf[i];
    }
    buf[SPX_N..SPX_BLAKE2S_BLOCK_BYTES].fill(0x36);
    inner_hasher.update(&buf[..SPX_BLAKE2S_BLOCK_BYTES]);

    // optrand || message
    inner_hasher.update(&optrand[..SPX_N]);
    inner_hasher.update(&m[..mlen]);

    let mut inner_hash = [0u8; SPX_BLAKE2S_OUTPUT_BYTES];
    inner_hasher.finalize(&mut inner_hash);

    // Outer hash: H((K ^ opad) || inner_hash)
    let mut outer_hasher = CairoBlake2sState::new();

    // K ^ opad (0x5c)
    for i in 0..SPX_N {
        buf[i] = 0x5c ^ sk_prf[i];
    }
    buf[SPX_N..SPX_BLAKE2S_BLOCK_BYTES].fill(0x5c);
    outer_hasher.update(&buf[..SPX_BLAKE2S_BLOCK_BYTES]);
    outer_hasher.update(&inner_hash);

    let mut outer_hash = [0u8; SPX_BLAKE2S_OUTPUT_BYTES];
    outer_hasher.finalize(&mut outer_hash);

    r[..SPX_N].copy_from_slice(&outer_hash[..SPX_N]);
}

/// Computes the message hash using R, the public key, and the message.
/// Outputs the message digest and the index of the leaf.
pub fn hash_message(
    digest: &mut [u8],
    tree: &mut u64,
    leaf_idx: &mut u32,
    R: &[u8],
    pk: &[u8],
    m: &[u8],
    mlen: usize,
    _ctx: &SpxCtx,
) {
    // seed = Blake2s(R || PK.seed || PK.root || M)
    let mut seed_hasher = CairoBlake2sState::new();
    seed_hasher.update(&R[..SPX_N]);
    seed_hasher.update(&pk[..SPX_PK_BYTES]);
    seed_hasher.update(&m[..mlen]);

    let mut seed = [0u8; 2 * SPX_N + SPX_BLAKE2S_OUTPUT_BYTES];
    seed[..SPX_N].copy_from_slice(&R[..SPX_N]);
    seed[SPX_N..SPX_N * 2].copy_from_slice(&pk[..SPX_N]);
    seed_hasher.finalize(&mut seed[2 * SPX_N..]);

    // H_msg: MGF1-Blake2s(R || PK.seed || seed)
    // We need the full 32 bytes because Cairo's digest structure is:
    // - bytes 0-27: words[0..7] (7 full u32 words)
    // - bytes 30-31: upper 2 bytes of word[7] (used for leaf_idx)
    // - bytes 28-29: lower 2 bytes of word[7] (NOT used in digest!)
    let mut buf = [0u8; SPX_BLAKE2S_OUTPUT_BYTES];  // 32 bytes
    mgf1_blake2s(&mut buf, SPX_BLAKE2S_OUTPUT_BYTES, &seed);

    // Extract mhash (21 bytes for 128s)
    // Cairo's split_xdigest_128s constructs mhash as:
    // - bytes 0-19: first 5 words (words[0..5])
    // - byte 20: MSB of word[5] (i.e., buf[23] in little-endian storage)
    // So mhash[20] = buf[23], NOT buf[20]!
    digest[..20].copy_from_slice(&buf[..20]);
    digest[20] = buf[23];  // MSB of word[5]

    // Extract tree and leaf_idx matching Cairo's split_xdigest_128s
    // Cairo treats the hash output as u32 words in little-endian byte order:
    // - word[5] (bytes 20-23): 8 bits mhash + 2 bits unused + 22 bits tree_hi
    // - word[6] (bytes 24-27): 32 bits tree_lo
    // - word[7] (bytes 28-31): upper 16 bits = last_word for leaf_idx
    //
    // tree_address (54 bits) = tree_hi << 32 | tree_lo
    // leaf_idx (9 bits) = (word7 >> 16) & 0x1FF

    let word5 = u32::from_le_bytes(buf[20..24].try_into().unwrap());
    let word6 = u32::from_le_bytes(buf[24..28].try_into().unwrap());
    let word7 = u32::from_le_bytes(buf[28..32].try_into().unwrap());

    let last_word = (word7 >> 16) as u16;  // upper 16 bits of word7
    *leaf_idx = (last_word & 0x1FF) as u32;  // 9 LSB bits

    let tree_hi = (word5 & 0x3FFFFF) as u64;  // bottom 22 bits of word5
    let tree_lo = word6 as u64;               // full 32 bits of word6
    *tree = (tree_hi << 32) | tree_lo;        // 54 bits total
}

/// MGF1 function based on Cairo-compatible Blake2s
fn mgf1_blake2s(out: &mut [u8], outlen: usize, input: &[u8]) {
    let inlen = 2 * SPX_N + SPX_BLAKE2S_OUTPUT_BYTES;
    let mut counter_buf = [0u8; 4];

    let mut i = 0;
    let mut idx = 0;
    while (i + 1) * SPX_BLAKE2S_OUTPUT_BYTES <= outlen {
        let mut hasher = CairoBlake2sState::new();
        hasher.update(&input[..inlen]);
        u32_to_bytes(&mut counter_buf, i as u32);
        hasher.update(&counter_buf);
        hasher.finalize(&mut out[idx..]);
        idx += SPX_BLAKE2S_OUTPUT_BYTES;
        i += 1;
    }

    // Fill the remainder
    if outlen > i * SPX_BLAKE2S_OUTPUT_BYTES {
        let mut hasher = CairoBlake2sState::new();
        hasher.update(&input[..inlen]);
        u32_to_bytes(&mut counter_buf, i as u32);
        hasher.update(&counter_buf);
        let mut outbuf = [0u8; SPX_BLAKE2S_OUTPUT_BYTES];
        hasher.finalize(&mut outbuf);
        let end = outlen - i * SPX_BLAKE2S_OUTPUT_BYTES;
        out[idx..idx + end].copy_from_slice(&outbuf[..end]);
    }
}
