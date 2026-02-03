# SPHINCS+ Test Data Generator

This directory contains a modified version of the [pqc_sphincsplus](https://github.com/Argyle-Software/sphincsplus) Rust crate, used to generate test signatures for the Cairo SPHINCS+ verifier.

## Credits

Original implementation by **Mitchell Berry** ([Argyle Software](https://github.com/Argyle-Software/sphincsplus)), licensed under MIT/Apache-2.0.

## Supported Hash Functions

- **SHA2** (default) - Standard SPHINCS+ with SHA-256
- **Blake2s** - Cairo-optimized variant with sparse address format

## Quick Start

```bash
# From the repository root

# SHA2 variant
make sphincs-args              # Generate test data
make sphincs-execute-sha2      # Verify in Cairo

# Blake2s variant
make sphincs-args-blake2s      # Generate test data
make sphincs-execute           # Verify in Cairo
make sphincs-test-blake2s      # Run Rust unit tests
make sphincs-verify-blake2s    # Run Rust e2e verification
```

## Modifications

### Big-endian address byte ordering (SHA2)

The standard SPHINCS+ implementation uses native endianness for address bytes. This version uses big-endian ordering for SHA2 mode to match Cairo's native integer representation.

### Sparse address format (Blake2s)

For Blake2s mode, addresses use a sparse format (8 u32 words) matching Cairo's `Address` struct:
- Word 0: layer
- Word 1: hypertree_addr_hi
- Word 2: hypertree_addr_lo
- Word 3: address_type
- Word 4: keypair
- Word 5: tree_height
- Word 6: tree_index
- Word 7: wots_addr (chain_idx * 0x100 + hash_position)

### Custom Blake2s implementation

The Blake2s variant uses a custom implementation that matches Cairo's `blake2s_compress`/`blake2s_finalize` builtins, allowing pre-computed state reuse in thash operations.

## Building manually

```bash
cd packages/sphincs-plus/scripts

# SHA2 (default)
cargo +nightly run --release --example generate_cairo_data

# Blake2s
cargo +nightly run --release --no-default-features \
  --features "blake2s,sparse_addr,s128,simple" \
  --example generate_cairo_data
```
