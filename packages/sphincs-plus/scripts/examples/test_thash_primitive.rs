//! Test thash primitive to compare with Cairo
//!
//! This verifies that our Rust Blake2s implementation matches Cairo's thash_4 exactly.
//!
//! Run with: cargo +nightly run --no-default-features --features "blake2s,sparse_addr,s128,simple" --example test_thash_primitive

use pqc_sphincsplus::context::SpxCtx;
use pqc_sphincsplus::blake2s::seed_state;
use pqc_sphincsplus::thash::thash;

fn main() {
    println!("=== Testing thash Primitive (Blake2s) ===\n");

    // Test data matching Cairo's test_thash_4_blake:
    // pk_seed = [1350675573, 3521007802, 3973994890, 3022267814]
    let pk_seed_words: [u32; 4] = [1350675573, 3521007802, 3973994890, 3022267814];

    println!("pk_seed as u32 words:");
    for (i, w) in pk_seed_words.iter().enumerate() {
        println!("  [{}]: {} (0x{:08x})", i, w, w);
    }

    // Convert to bytes
    let mut pk_seed = [0u8; 16];
    for (i, w) in pk_seed_words.iter().enumerate() {
        pk_seed[i*4..i*4+4].copy_from_slice(&w.to_le_bytes());
    }

    // Initialize context
    let mut ctx = SpxCtx::default();
    ctx.pub_seed.copy_from_slice(&pk_seed);
    seed_state(&mut ctx);

    // Address: all zeros
    let addr = [0u32; 8];
    println!("\naddr: {:?}", addr);

    // Data: [0x11111111, 0x22222222, 0x33333333, 0x44444444]
    let data_words: [u32; 4] = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
    let mut data = [0u8; 16];
    for (i, w) in data_words.iter().enumerate() {
        data[i*4..i*4+4].copy_from_slice(&w.to_le_bytes());
    }
    println!("data as u32 words: {:?}", data_words);

    // Compute thash
    let mut output = [0u8; 16];
    output.copy_from_slice(&data);
    thash::<1>(&mut output, Some(&data), &ctx, &addr);

    // Convert output to u32 words
    let output_words: Vec<u32> = output.chunks(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();

    println!("\n=== Result ===");
    println!("thash::<1> output: {:?}", output_words);

    // Expected from Cairo test_thash_4_blake:
    // [240554214, 3442018119, 167305318, 1154638756]
    let expected: [u32; 4] = [240554214, 3442018119, 167305318, 1154638756];
    println!("Expected from Cairo: {:?}", expected);
    println!("Match: {}", output_words == expected.to_vec());
}
