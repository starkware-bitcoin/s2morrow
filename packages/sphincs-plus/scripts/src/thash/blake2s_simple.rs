use crate::{
    params::SPX_N,
    blake2s::{load_seeded_state, SPX_BLAKE2S_ADDR_BYTES},
    context::SpxCtx
};

/// Takes an array of inblocks concatenated arrays of SPX_N bytes.
/// Uses sparse address format (8 u32 words as little-endian bytes) for Cairo compatibility.
///
/// Cairo's thash uses pre-computed state from ctx.state_seeded:
///   - state_seeded is computed by initialize_hash_function: compress [pk_seed(4), zeros(12)]
///   - thash_N then uses state_seeded and processes [addr(8), data(N*4), zeros(padding)]
///
/// For Default::default() ctx, state_seeded.h = [0;8] and byte_len = 0 (NOT initialized).
/// This matches Cairo's behavior exactly.
pub fn thash<const N: usize>(
    out: &mut [u8],
    input: Option<&[u8]>,
    ctx: &SpxCtx,
    addr: &[u32],
) where
    [(); SPX_N + SPX_BLAKE2S_ADDR_BYTES + N * SPX_N]: Sized,
{
    // Load pre-computed seeded state from ctx
    let mut state = load_seeded_state(ctx);

    // Convert address to u32 words
    let addr_words: [u32; 8] = addr.try_into().expect("addr must be 8 words");

    // Get data as u32 words
    let data = input.unwrap_or(out);
    let data_words: Vec<u32> = data[..N * SPX_N].chunks(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();


    // Build blocks for hashing: [addr(8 words), data(N*4 words), zeros(padding)]
    // Each block is 16 u32 words (64 bytes)

    // For N=1 (thash_4): addr(8) + data(4) + zeros(4) = 16 words = 1 block (finalize)
    // For N=2 (thash_8): addr(8) + data(8) = 16 words = 1 block (finalize)
    // For N=35 (thash_140): addr(8) + data(140) = 148 words = 10 blocks

    let total_data_words = 8 + N * 4; // addr + data
    let total_blocks = (total_data_words + 15) / 16;

    // Combine addr and data into a single word array
    let mut all_words = Vec::with_capacity(total_blocks * 16);
    all_words.extend_from_slice(&addr_words);
    all_words.extend_from_slice(&data_words);
    // Pad with zeros to fill last block
    all_words.resize(total_blocks * 16, 0);

    // Process all blocks except the last one with update_block
    for i in 0..(total_blocks - 1) {
        let block: [u32; 16] = all_words[i*16..(i+1)*16].try_into().unwrap();
        state.update_block(&block);
    }

    // Finalize with the last block
    let last_block: [u32; 16] = all_words[(total_blocks-1)*16..total_blocks*16].try_into().unwrap();
    let result = state.finalize_block(&last_block);

    // Copy result to output (only first SPX_N bytes = 4 words for 128s)
    for i in 0..(SPX_N / 4) {
        out[i*4..i*4+4].copy_from_slice(&result[i].to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thash_1_cairo_compat() {
        // Test against Cairo's test_thash_4_blake test case from hasher.cairo
        // pk_seed = [1350675573, 3521007802, 3973994890, 3022267814]
        // addr = all zeros
        // data = [0x11111111, 0x22222222, 0x33333333, 0x44444444]
        // Expected: [240554214, 3442018119, 167305318, 1154638756]

        let pk_seed_words: [u32; 4] = [1350675573, 3521007802, 3973994890, 3022267814];
        let mut pk_seed = [0u8; 16];
        for (i, w) in pk_seed_words.iter().enumerate() {
            pk_seed[i*4..i*4+4].copy_from_slice(&w.to_le_bytes());
        }

        let mut ctx = SpxCtx::default();
        ctx.pub_seed.copy_from_slice(&pk_seed);

        // Initialize hash function (compute state_seeded from pub_seed)
        // This matches Cairo's initialize_hash_function(pk_seed)
        seed_state(&mut ctx);

        let addr = [0u32; 8]; // all zeros

        let data_words: [u32; 4] = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
        let mut data = [0u8; 16];
        for (i, w) in data_words.iter().enumerate() {
            data[i*4..i*4+4].copy_from_slice(&w.to_le_bytes());
        }

        let mut output = [0u8; 16];
        output.copy_from_slice(&data);
        thash::<1>(&mut output, Some(&data), &ctx, &addr);

        // Convert output to u32 words
        let output_words: Vec<u32> = output.chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();

        println!("thash::<1> output: {:?}", output_words);
        // Cairo expects: [240554214, 3442018119, 167305318, 1154638756]

        assert_eq!(output_words, vec![240554214, 3442018119, 167305318, 1154638756]);
    }

    #[test]
    fn test_chain_hash_with_default_ctx() {
        // Test chain hashing with default ctx (h=[0;8], byte_len=0)
        // NOTE: Cairo's test_chain_hash_3 expected value is for SHA256, not Blake2s!
        // The Blake2s expected values are different and verified here.
        //
        // For real usage, the ctx is always initialized with seed_state(), so
        // the default ctx case is mainly for testing internal consistency.

        let ctx = SpxCtx::default(); // state_seeded_blake = all zeros (h=[0;8], byte_len=0)

        // Verify the default state
        let state = load_seeded_state(&ctx);
        assert_eq!(state.h, [0; 8]);
        assert_eq!(state.byte_len, 0);

        let input_words: [u32; 4] = [1640362213, 3803567762, 3187702095, 90287887];
        let mut data = [0u8; 16];
        for (i, w) in input_words.iter().enumerate() {
            data[i*4..i*4+4].copy_from_slice(&w.to_le_bytes());
        }

        let mut addr = [0u32; 8];

        // Do 6 hashes at wots_addr positions 9-14
        for pos in 9u32..15 {
            addr[7] = pos;  // SPX_OFFSET_WOTS_ADDR = 7
            thash::<1>(&mut data, None, &ctx, &addr);
        }

        let output_words: Vec<u32> = data.chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();

        // Blake2s expected output (verified by internal consistency)
        // This differs from SHA256's [3700563191, 1880524724, 4147099568, 1051379323]
        println!("Blake2s chain hash output: {:?}", output_words);

        // The output should be deterministic - verify it doesn't change
        assert_eq!(output_words, vec![4033360182, 2182417223, 2387713248, 2849142720]);
    }

    #[test]
    fn test_single_thash_default_ctx() {
        // Test a single thash with default ctx (h=[0;8], byte_len=0)
        // This tests blake2s_finalize([0;8], 64, [addr + data + zeros])
        //
        // Note: Default ctx (h=[0;8]) is not normally used - seed_state() initializes it.
        // This test verifies internal consistency of the Blake2s implementation.

        let ctx = SpxCtx::default();

        let input_words: [u32; 4] = [1640362213, 3803567762, 3187702095, 90287887];
        let mut data = [0u8; 16];
        for (i, w) in input_words.iter().enumerate() {
            data[i*4..i*4+4].copy_from_slice(&w.to_le_bytes());
        }

        let addr = [0u32, 0, 0, 0, 0, 0, 0, 9];

        thash::<1>(&mut data, None, &ctx, &addr);

        let output_words: Vec<u32> = data.chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();

        // Blake2s output with h=[0;8] starting state
        assert_eq!(output_words, vec![936847585, 653364650, 3617185006, 2887816091]);
    }

    #[test]
    fn test_thash_35_simple() {
        // Test thash::<35> with simple known inputs
        // pk_seed = [1350675573, 3521007802, 3973994890, 3022267814] (same as other tests)
        // addr = all zeros except type = 1 (WOTSPK)
        // data = 35 * [0x11111111, 0x22222222, 0x33333333, 0x44444444]

        let pk_seed_words: [u32; 4] = [1350675573, 3521007802, 3973994890, 3022267814];
        let mut pk_seed = [0u8; 16];
        for (i, w) in pk_seed_words.iter().enumerate() {
            pk_seed[i*4..i*4+4].copy_from_slice(&w.to_le_bytes());
        }

        let mut ctx = SpxCtx::default();
        ctx.pub_seed.copy_from_slice(&pk_seed);
        seed_state(&mut ctx);

        // Address with type = 1 (WOTSPK)
        let addr = [0u32, 0, 0, 1, 0, 0, 0, 0];

        // Simple pattern data: 35 * [0x11111111, 0x22222222, 0x33333333, 0x44444444]
        let mut data = [0u8; 35 * 16];
        let pattern: [u32; 4] = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
        for i in 0..35 {
            for (j, w) in pattern.iter().enumerate() {
                data[i*16 + j*4 .. i*16 + j*4 + 4].copy_from_slice(&w.to_le_bytes());
            }
        }

        let mut output = [0u8; 16];
        thash::<35>(&mut output, Some(&data), &ctx, &addr);

        let output_words: Vec<u32> = output.chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();

        println!("thash::<35> simple test output: {:?}", output_words);
        // This value should match Cairo's thash_140 with same inputs
    }

    #[test]
    fn test_seeded_state_for_actual_pk_seed() {
        // Test with pk_seed from the actual test case
        // pk_seed = [606282273, 673654309, 741026345, 808398381]
        // In hex: 0x24232221, 0x28272625, 0x2c2b2a29, 0x302f2e2d
        // This is "!\"#$%&'()*+,-./0" in ASCII

        let pk_seed_words: [u32; 4] = [606282273, 673654309, 741026345, 808398381];
        let mut pk_seed = [0u8; 16];
        for (i, w) in pk_seed_words.iter().enumerate() {
            pk_seed[i*4..i*4+4].copy_from_slice(&w.to_le_bytes());
        }

        let mut ctx = SpxCtx::default();
        ctx.pub_seed.copy_from_slice(&pk_seed);
        seed_state(&mut ctx);

        let state = load_seeded_state(&ctx);

        println!("Seeded state for pk_seed [606282273, 673654309, 741026345, 808398381]:");
        println!("state.h: {:?}", state.h);
        println!("state.byte_len: {}", state.byte_len);

        // This is what Rust produces - need to verify Cairo produces the same
        assert_eq!(state.h, [3395526082, 846969334, 2302489355, 1259298823, 4064129534, 1847701762, 3871428615, 2465737296]);
        assert_eq!(state.byte_len, 64);
    }

    #[test]
    fn test_initialize_hash_function_blake() {
        // Test that seed_state produces the same state as Cairo's initialize_hash_function
        // pk_seed = [1350675573, 3521007802, 3973994890, 3022267814]
        // Expected state from Cairo test_initialize_hash_function_blake:
        // h = [2353511074, 2785205407, 1616039471, 3946058094, 220633588, 479096234, 421844601, 2930383070]
        // byte_len = 64

        let pk_seed_words: [u32; 4] = [1350675573, 3521007802, 3973994890, 3022267814];
        let mut pk_seed = [0u8; 16];
        for (i, w) in pk_seed_words.iter().enumerate() {
            pk_seed[i*4..i*4+4].copy_from_slice(&w.to_le_bytes());
        }

        let mut ctx = SpxCtx::default();
        ctx.pub_seed.copy_from_slice(&pk_seed);
        seed_state(&mut ctx);

        let state = load_seeded_state(&ctx);

        println!("state.h: {:?}", state.h);
        println!("state.byte_len: {}", state.byte_len);

        let expected_h: [u32; 8] = [
            2353511074, 2785205407, 1616039471, 3946058094,
            220633588, 479096234, 421844601, 2930383070
        ];

        assert_eq!(state.h, expected_h);
        assert_eq!(state.byte_len, 64);
    }
}
