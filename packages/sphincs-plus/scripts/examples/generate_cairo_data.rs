use pqc_sphincsplus::*;

#[cfg(not(feature = "blake2s"))]
fn bytes_to_u32_be(data: &[u8]) -> Vec<u32> {
    data.chunks(4)
        .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
        .collect()
}

#[cfg(feature = "blake2s")]
fn bytes_to_u32_le(data: &[u8]) -> Vec<u32> {
    data.chunks(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect()
}

fn main() {
    // Generate keypair with deterministic seed
    // Seed is CRYPTO_SEEDBYTES = 3 * SPX_N = 48 bytes for 128-bit security
    let seed: [u8; 48] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    ];
    let keys = keypair_from_seed(&seed);

    // 64 bytes of 0x1b as message (matches existing test data)
    let msg: [u8; 64] = [0x1b; 64];

    // Sign the message
    let sig = sign(&msg, &keys);

    // Convert to u32 arrays
    // For Blake2s mode, use little-endian (Cairo compatibility)
    // For other modes, use big-endian (original behavior)
    #[cfg(feature = "blake2s")]
    let (pk_u32, sig_u32, msg_u32) = (
        bytes_to_u32_le(&keys.public),
        bytes_to_u32_le(&sig),
        bytes_to_u32_le(&msg),
    );

    #[cfg(not(feature = "blake2s"))]
    let (pk_u32, sig_u32, msg_u32) = (
        bytes_to_u32_be(&keys.public),
        bytes_to_u32_be(&sig),
        bytes_to_u32_be(&msg),
    );

    // Build Cairo format: pk + sig + msg_word_count + msg_words + padding
    let mut result: Vec<String> = Vec::new();

    // Add public key (8 u32)
    for v in &pk_u32 {
        result.push(format!("\"0x{:x}\"", v));
    }

    // Add signature (1964 u32)
    for v in &sig_u32 {
        result.push(format!("\"0x{:x}\"", v));
    }

    // Add message word count
    result.push(format!("\"0x{:x}\"", msg_u32.len()));

    // Add message words
    for v in &msg_u32 {
        result.push(format!("\"0x{:x}\"", v));
    }

    // Add padding (2 zeros)
    result.push("\"0x0\"".to_string());
    result.push("\"0x0\"".to_string());

    // Output as JSON array
    println!("[{}]", result.join(","));
}
