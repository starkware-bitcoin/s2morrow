//! Test Blake2s initialization to compare with Cairo
//!
//! Run with: cargo +nightly run --no-default-features --features "blake2s,sparse_addr,s128,simple" --example test_blake2s_init

use pqc_sphincsplus::context::SpxCtx;
use pqc_sphincsplus::blake2s::{seed_state, load_seeded_state, BLAKE2S_256_IV};

fn main() {
    // Cairo test_initialize_hash_function uses pk_seed = [1350675573, 3521007802, 3973994890, 3022267814]
    let pk_seed_words: [u32; 4] = [1350675573, 3521007802, 3973994890, 3022267814];

    println!("=== Testing Blake2s Initialization ===\n");
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

    // Load and print the seeded state
    let state = load_seeded_state(&ctx);

    println!("\n=== Blake2s IV (modified for 32-byte output) ===");
    for (i, w) in BLAKE2S_256_IV.iter().enumerate() {
        println!("  [{}]: {} (0x{:08x})", i, w, w);
    }

    println!("\n=== State after seed_state() ===");
    println!("h: {:?}", state.h);
    println!("byte_len: {}", state.byte_len);

    // Expected from Cairo test_initialize_hash_function_blake:
    // h = [2353511074, 2785205407, 1616039471, 3946058094, 220633588, 479096234, 421844601, 2930383070]
    // byte_len = 64
    let expected_h: [u32; 8] = [
        2353511074, 2785205407, 1616039471, 3946058094,
        220633588, 479096234, 421844601, 2930383070
    ];

    println!("\n=== Expected from Cairo ===");
    println!("h: {:?}", expected_h);
    println!("byte_len: 64");

    println!("\n=== Verification ===");
    println!("h matches: {}", state.h == expected_h);
    println!("byte_len matches: {}", state.byte_len == 64);
}
