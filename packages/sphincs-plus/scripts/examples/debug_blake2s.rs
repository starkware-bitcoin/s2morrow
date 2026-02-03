//! Debug script to print intermediate Blake2s values for comparison with Cairo
//!
//! Run with: cargo +nightly run --no-default-features --features "blake2s,sparse_addr,s128,simple" --example debug_blake2s

use pqc_sphincsplus::blake2s::{blake2s, CairoBlake2sState, BLAKE2S_256_IV};

fn main() {
    // Use fixed seeds for reproducibility
    let pk_seed: [u8; 16] = [
        0xd3, 0x22, 0xf6, 0x17, 0xa9, 0xa6, 0xd9, 0x3f,
        0x4a, 0x6b, 0x10, 0xd0, 0x5d, 0x69, 0x7b, 0x42,
    ];
    let sk_seed: [u8; 16] = [
        0xd7, 0xb5, 0x0d, 0x8d, 0xb9, 0xd3, 0xea, 0xcb,
        0x5c, 0xce, 0x8e, 0x15, 0xf7, 0xba, 0xbc, 0xaa,
    ];

    println!("=== Debug Blake2s Implementation ===\n");

    // Print seeds as u32 words (little-endian, as Cairo expects)
    println!("pk_seed as LE u32 words:");
    for i in 0..4 {
        let word = u32::from_le_bytes(pk_seed[i*4..i*4+4].try_into().unwrap());
        println!("  [{}]: 0x{:08x}", i, word);
    }

    println!("\nsk_seed as LE u32 words:");
    for i in 0..4 {
        let word = u32::from_le_bytes(sk_seed[i*4..i*4+4].try_into().unwrap());
        println!("  [{}]: 0x{:08x}", i, word);
    }

    // Print Blake2s IV
    println!("\n=== Blake2s-256 IV (with param block XOR) ===");
    for (i, w) in BLAKE2S_256_IV.iter().enumerate() {
        println!("  [{}]: 0x{:08x}", i, w);
    }

    // Test a simple Blake2s hash
    println!("\n=== Testing simple Blake2s hash ===");

    // Hash 32 zero bytes
    let input = [0u8; 32];
    println!("Input: 32 zero bytes");

    let mut result = [0u8; 32];
    blake2s(&mut result, &input, 32);

    println!("\nBlake2s output as u32 LE words:");
    for i in 0..8 {
        let word = u32::from_le_bytes(result[i*4..i*4+4].try_into().unwrap());
        println!("  [{}]: 0x{:08x}", i, word);
    }

    // Test thash structure
    println!("\n=== Testing thash_4 structure ===");
    println!("Cairo thash_4 does:");
    println!("1. Uses pre-computed state_seeded from compress([pk_seed(4) || zeros(12)])");
    println!("2. Finalize: [address(8) || data(4) || zeros(4)] = 64 bytes");

    // Simulate the structure
    let address: [u32; 8] = [0, 0, 0, 0, 0, 0, 0, 0]; // all zeros for test
    let data: [u32; 4] = [0x11111111, 0x22222222, 0x33333333, 0x44444444];

    println!("\nTest address (8 words): all zeros");
    println!("Test data (4 words): 0x11111111, 0x22222222, 0x33333333, 0x44444444");

    // Build the blocks as Cairo would see them
    let mut block1 = [0u8; 64];
    for i in 0..4 {
        let word = u32::from_le_bytes(pk_seed[i*4..i*4+4].try_into().unwrap());
        block1[i*4..i*4+4].copy_from_slice(&word.to_le_bytes());
    }
    // Rest is zeros

    println!("\nBlock 1 (seed block) as u32 words:");
    for i in 0..16 {
        let word = u32::from_le_bytes(block1[i*4..i*4+4].try_into().unwrap());
        if word != 0 || i < 4 {
            println!("  [{}]: 0x{:08x}", i, word);
        }
    }

    let mut block2 = [0u8; 64];
    // Address (8 words)
    for i in 0..8 {
        block2[i*4..i*4+4].copy_from_slice(&address[i].to_le_bytes());
    }
    // Data (4 words)
    for i in 0..4 {
        block2[(8+i)*4..(8+i)*4+4].copy_from_slice(&data[i].to_le_bytes());
    }
    // Rest is zeros (4 words)

    println!("\nBlock 2 (addr+data block) as u32 words:");
    for i in 0..16 {
        let word = u32::from_le_bytes(block2[i*4..i*4+4].try_into().unwrap());
        println!("  [{}]: 0x{:08x}", i, word);
    }
}
