# SPHINCS+ Test Data Generator

This directory contains a modified version of the [pqc_sphincsplus](https://github.com/Argyle-Software/sphincsplus) Rust crate, used to generate test signatures for the Cairo SPHINCS+ verifier.

## Credits

Original implementation by **Mitchell Berry** ([Argyle Software](https://github.com/Argyle-Software/sphincsplus)), licensed under MIT/Apache-2.0.

## Modifications

### Big-endian address byte ordering

The standard SPHINCS+ implementation uses native endianness for address bytes (`to_ne_bytes`/`from_ne_bytes`). This version uses big-endian ordering (`to_be_bytes`/`from_be_bytes`) instead.

**Why?** Cairo's native integer representation is big-endian. Using big-endian address bytes in the signature allows the Cairo verifier to work with addresses directly without byte-swapping, simplifying the implementation and reducing the number of operations.

The changes are in `src/address.rs`:
- `from_ne_bytes` → `from_be_bytes`
- `to_ne_bytes` → `to_be_bytes`

## Usage

Generate test data for Cairo:

```bash
# From the repository root
make sphincs-args
```

This will:
1. Build the Rust crate with nightly (required for `generic_const_exprs`)
2. Run the `generate_cairo_data` example
3. Output JSON to `tests/data/sha2_simple_128s.json`

## Building manually

```bash
cd packages/sphincs-plus/scripts
cargo +nightly run --release --example generate_cairo_data
```
