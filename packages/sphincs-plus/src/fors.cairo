// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! FORS (Forest of Random Subsets) is a few-times signature (FTS) scheme.
//! See https://research.dorahacks.io/2022/12/16/hash-based-post-quantum-signatures-2/ for an
//! overview and https://www.di-mgt.com.au/pqc-09-fors-sig.html for a step-by-step construction.

use core::traits::DivRem;
use crate::address::{Address, AddressTrait, AddressType};
use crate::hasher::{HashOutput, SpxCtx, compute_root, thash_4, thash_56};
use crate::params_128s::{SPX_FORS_BASE_OFFSET, SPX_FORS_HEIGHT, SPX_FORS_TREES};
use crate::word_array::{WordSpan, WordSpanTrait};

/// FORS signature.
pub type ForsSignature = [ForsTreeSignature; SPX_FORS_TREES];

/// FORS tree signature.
#[derive(Drop, Copy, Serde, Default)]
pub struct ForsTreeSignature {
    pub sk_seed: HashOutput,
    pub auth_path: [HashOutput; SPX_FORS_HEIGHT],
}

/// Derive FORS public key from a signature.
pub fn fors_pk_from_sig(
    ctx: SpxCtx, mut sig: ForsSignature, mhash: WordSpan, address: @Address,
) -> HashOutput {
    let mut fors_tree_addr = address.clone();
    fors_tree_addr.set_address_type(AddressType::FORSTREE);

    // Compute indices of leaves of the FORS trees
    let mut indices = message_to_indices_128s(mhash);
    // Offset for the leaves indices
    let mut idx_offset = 0;
    // FORS roots
    let mut roots = array![];

    let mut fors_sig = sig.span();

    while let Some(fors_tree_sig) = fors_sig.pop_front() {
        let ForsTreeSignature { sk_seed, auth_path } = *fors_tree_sig;
        let leaf_idx = indices.pop_front().unwrap();

        // NOTE: already zero `fors_tree_addr.set_tree_height(0);`
        fors_tree_addr.set_tree_index(idx_offset + leaf_idx);

        // Derive the leaf hash from the secret key seed and tree address.
        let leaf = thash_4(ctx, @fors_tree_addr, sk_seed);

        // Derive the corresponding root node of this tree.
        // Auth path has fixed length, so we don't need to assert tree height.
        let root = compute_root(ctx, @fors_tree_addr, leaf, auth_path.span(), leaf_idx, idx_offset);
        roots.append(root);

        idx_offset += SPX_FORS_BASE_OFFSET;
    }

    // Hash horizontally across all tree roots to derive the public key.
    let mut fors_pk_addr = address.clone();
    fors_pk_addr.set_address_type(AddressType::FORSPK);

    thash_56(ctx, @fors_pk_addr, roots.span())
}

/// Convert FORS mhash to leaves indices.
///
/// A simplified flow:
/// - reinterpret mhash as a little-endian integer
/// - calculate SPX_FORS_TREES remainders modulo SPX_FORS_HEIGHT
///
/// In other words, we are iterating over the mhash in reverse byte order,
/// interpreting every SPX_FORS_HEIGHT chunk of bits as a little-endian integer.
fn message_to_indices_128s(mut mhash: WordSpan) -> Array<u32> {
    let mut indices = array![];

    // Accumulator is the LSB "carry" from the previous word.
    let mut acc = 0;
    let mut acc_bits = 0;

    // Mhash structure: words are byte-reversed, we are going in LE order.
    // [8|4 4|8, 8] [4 4|8 8|4, 4] [8 8|4 4|8] [8|4 4|8, 8] [4 8|4 4|8, 4] [8]
    while let Some((mut word, num_bytes)) = mhash.pop_front() {
        if num_bytes == 4 {
            // Our word [ab cd ef gh] is in BE, we need to decompose it into bytes
            let (ab, cdefgh) = DivRem::div_rem(word, 0x1000000);
            let (cd, efgh) = DivRem::div_rem(cdefgh, 0x10000);
            let (ef, gh) = DivRem::div_rem(efgh, 0x100);

            if acc_bits == 0 { // [dab efc, gh]
                let (c, d) = DivRem::div_rem(cd, 0x10);
                indices.append(d * 0x100 + ab);
                indices.append(ef * 0x10 + c);
                acc = gh;
                acc_bits = 8;
            } else if acc_bits == 8 { // [bxx cda hef, g]
                let (a, b) = DivRem::div_rem(ab, 0x10);
                let (g, h) = DivRem::div_rem(gh, 0x10);
                indices.append(b * 0x100 + acc);
                indices.append(cd * 0x10 + a);
                indices.append(h * 0x100 + ef);
                acc = g;
                acc_bits = 4;
            } else if acc_bits == 4 { // [abx fcd ghe]
                let (e, f) = DivRem::div_rem(ef, 0x10);
                indices.append(ab * 0x10 + acc);
                indices.append(f * 0x100 + cd);
                indices.append(gh * 0x10 + e);
                acc = 0;
                acc_bits = 0;
            } else {
                assert(false, 'invalid acc_bits (4)');
            }
        } else if num_bytes == 1 { // [abx]
            // Last word is one byte (lowest)
            assert(acc_bits == 4, 'invalid acc_bits (1)');
            indices.append(word * 0x10 + acc);
        } else {
            assert(false, 'invalid mhash length');
        }
    }

    indices
}

#[cfg(test)]
mod tests {
    use crate::word_array::WordArrayTrait;
    use crate::word_array::hex::words_from_hex;
    use super::*;

    #[test]
    fn test_message_to_indices_128s() {
        let mhash = words_from_hex("6059c80500bb1e198b352d9edde57e7550ccc7a97e");
        assert_eq!(mhash.byte_len(), 21);
        let indices = message_to_indices_128s(mhash.span());
        let expected = array![
            2400, 3205, 5, 2992, 2334, 2225, 3381, 2530, 1501, 2030, 117, 3269, 2503, 2026,
        ];
        assert_eq!(expected, indices);
    }
}
