use pqc_sphincsplus::*;

fn bytes_to_u32_be(data: &[u8]) -> Vec<u32> {
    data.chunks(4)
        .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
        .collect()
}

fn main() {
    // Generate keypair
    let keys = keypair();

    // 64 bytes of 0x1b as message (matches existing test data)
    let msg: [u8; 64] = [0x1b; 64];

    // Sign the message
    let sig = sign(&msg, &keys);

    // Convert to u32 arrays (big-endian)
    let pk_u32 = bytes_to_u32_be(&keys.public);
    let sig_u32 = bytes_to_u32_be(&sig);
    let msg_u32 = bytes_to_u32_be(&msg);

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
