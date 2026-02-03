//! Debug signing to compare intermediate values with Cairo

use pqc_sphincsplus::*;
use std::fs;

fn main() {
    // Read the test data JSON
    let json = fs::read_to_string("../tests/data/blake2s_simple_128s.json")
        .expect("Failed to read test data");

    // Parse JSON array of hex strings
    let values: Vec<String> = serde_json::from_str(&json).expect("Failed to parse JSON");
    let words: Vec<u32> = values.iter()
        .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
        .collect();

    // Format: pk (8 words) + sig (1964 words) + msg_word_count (1) + msg (16 words) + padding (2)
    let pk_words = &words[0..8];
    let sig_words = &words[8..8+1964];
    let msg_word_count = words[8+1964] as usize;
    let msg_words = &words[8+1964+1..8+1964+1+msg_word_count];

    // Convert to bytes (little-endian)
    let mut pk = [0u8; 32];
    for i in 0..8 {
        pk[i*4..i*4+4].copy_from_slice(&pk_words[i].to_le_bytes());
    }

    let mut sig = [0u8; 7856];  // CRYPTO_BYTES for 128s
    for i in 0..1964 {
        sig[i*4..i*4+4].copy_from_slice(&sig_words[i].to_le_bytes());
    }

    let mut msg = [0u8; 64];
    for i in 0..msg_word_count {
        msg[i*4..i*4+4].copy_from_slice(&msg_words[i].to_le_bytes());
    }

    // Build Keypair (we only need public for verification)
    let keys = Keypair {
        public: pk,
        secret: [0u8; CRYPTO_SECRETKEYBYTES],
    };

    // Print debug info
    println!("=== Rust verify debug (from JSON) ===");
    let pk_seed = &pk[..16];
    let pk_root = &pk[16..32];

    print!("pk_seed: [");
    for i in 0..4 {
        let word = u32::from_le_bytes(pk_seed[i*4..i*4+4].try_into().unwrap());
        print!("{}", word);
        if i < 3 { print!(", "); }
    }
    println!("]");

    print!("pk_root: [");
    for i in 0..4 {
        let word = u32::from_le_bytes(pk_root[i*4..i*4+4].try_into().unwrap());
        print!("{}", word);
        if i < 3 { print!(", "); }
    }
    println!("]");

    // Extract randomizer (first 16 bytes of signature)
    let randomizer = &sig[..16];
    print!("randomizer: [");
    for i in 0..4 {
        let word = u32::from_le_bytes(randomizer[i*4..i*4+4].try_into().unwrap());
        print!("{}", word);
        if i < 3 { print!(", "); }
    }
    println!("]");

    // Add detailed debug output for comparison
    use pqc_sphincsplus::context::SpxCtx;
    use pqc_sphincsplus::blake2s::{seed_state, load_seeded_state};

    let mut ctx = SpxCtx::default();
    ctx.pub_seed.copy_from_slice(&pk[..16]);
    seed_state(&mut ctx);

    let state = load_seeded_state(&ctx);
    print!("seeded state.h: [");
    for (i, h) in state.h.iter().enumerate() {
        print!("{}", h);
        if i < 7 { print!(", "); }
    }
    println!("]");
    println!("seeded state.byte_len: {}", state.byte_len);

    // Verify the signature
    let result = verify(&sig, &msg, &keys);
    println!("Rust verify result: {}", result.is_ok());
}
