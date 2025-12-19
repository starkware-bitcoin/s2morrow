// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

// Available hash functions.
mod blake2s;
mod sha256;

// Cairo-friendly hash function (custom AIR in Stwo)
#[cfg(feature: "blake_hash")]
pub use blake2s::{
    HashState, hash_finalize, hash_finalize_block, hash_init, hash_update, hash_update_block,
};

// Default hash function according to the sha256-128s parameters.
#[cfg(not(feature: "blake_hash"))]
pub use sha256::{HashState, hash_finalize, hash_init, hash_update, hash_update_block};

// Imports.
use crate::address::{Address, AddressTrait, AddressType};
use crate::params_128s::SPX_HASH_LEN;
use crate::word_array::{WordArray, WordArrayTrait, WordSpan, WordSpanTrait};

/// Hash output.
pub type HashOutput = [u32; SPX_HASH_LEN];

/// Hash context.
#[derive(Drop, Copy, Default, Debug)]
pub struct SpxCtx {
    state_seeded: HashState,
}

/// Absorb the constant pub_seed using one round of the compression function
/// This initializes state_seeded and state_seeded_512, which can then be
/// reused input thash
pub fn initialize_hash_function(pk_seed: HashOutput) -> SpxCtx {
    let mut state: HashState = Default::default();
    let [a, b, c, d] = pk_seed;
    hash_init(ref state);
    hash_update_block(ref state, [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    SpxCtx { state_seeded: state }
}

#[cfg(feature: "blake_hash")]
pub fn thash_4(ctx: SpxCtx, address: @Address, data: [u32; 4]) -> HashOutput {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = address.into_components();
    let [d0, d1, d2, d3] = data;
    let mut state = ctx.state_seeded;
    let [h0, h1, h2, h3, _, _, _, _] = hash_finalize_block(
        ref state, [a0, a1, a2, a3, a4, a5, a6, a7, d0, d1, d2, d3, 0, 0, 0, 0],
    );
    [h0, h1, h2, h3]
}

#[cfg(not(feature: "blake_hash"))]
pub fn thash_4(ctx: SpxCtx, address: @Address, data: [u32; 4]) -> HashOutput {
    let mut buffer = address.to_word_array();
    buffer.append_u32_span(data.span());
    thash_128s(ctx, address, buffer)
}

#[cfg(feature: "blake_hash")]
pub fn thash_5(ctx: SpxCtx, address: @Address, word0: [u32; 4], word1: u32) -> HashOutput {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = address.into_components();
    let [d0, d1, d2, d3] = word0;
    let d4 = word1;
    let mut state = ctx.state_seeded;
    let [h0, h1, h2, h3, _, _, _, _] = hash_finalize_block(
        ref state, [a0, a1, a2, a3, a4, a5, a6, a7, d0, d1, d2, d3, d4, 0, 0, 0],
    );
    [h0, h1, h2, h3]
}

#[cfg(not(feature: "blake_hash"))]
pub fn thash_5(ctx: SpxCtx, address: @Address, word0: [u32; 4], word1: u32) -> HashOutput {
    let mut buffer = address.to_word_array();
    buffer.append_u32_span(word0.span());
    buffer.append_u32_be(word1);
    thash_128s(ctx, address, buffer)
}

#[cfg(feature: "blake_hash")]
pub fn thash_8(ctx: SpxCtx, address: @Address, word0: [u32; 4], word1: [u32; 4]) -> HashOutput {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = address.into_components();
    let [d0, d1, d2, d3] = word0;
    let [d4, d5, d6, d7] = word1;
    let mut state = ctx.state_seeded;
    let [h0, h1, h2, h3, _, _, _, _] = hash_finalize_block(
        ref state, [a0, a1, a2, a3, a4, a5, a6, a7, d0, d1, d2, d3, d4, d5, d6, d7],
    );
    [h0, h1, h2, h3]
}

#[cfg(not(feature: "blake_hash"))]
pub fn thash_8(ctx: SpxCtx, address: @Address, word0: [u32; 4], word1: [u32; 4]) -> HashOutput {
    let mut buffer = address.to_word_array();
    buffer.append_u32_span(word0.span());
    buffer.append_u32_span(word1.span());
    thash_128s(ctx, address, buffer)
}

#[cfg(feature: "blake_hash")]
pub fn thash_140(ctx: SpxCtx, address: @Address, mut data: Span<[u32; 4]>) -> HashOutput {
    let mut state = ctx.state_seeded;
    let (a0, a1, a2, a3, a4, a5, a6, a7) = address.into_components();

    let Some(block) = data.multi_pop_front::<2>() else {
        panic!("thash_140: expected len = 10");
    };
    let [w0, w1] = (*block).unbox();
    let [d0, d1, d2, d3] = w0;
    let [d4, d5, d6, d7] = w1;
    hash_update_block(ref state, [a0, a1, a2, a3, a4, a5, a6, a7, d0, d1, d2, d3, d4, d5, d6, d7]);

    while let Some(block) = data.multi_pop_front::<4>() {
        let [w0, w1, w2, w3] = (*block).unbox();
        let [d0, d1, d2, d3] = w0;
        let [d4, d5, d6, d7] = w1;
        let [d8, d9, d10, d11] = w2;
        let [d12, d13, d14, d15] = w3;
        hash_update_block(
            ref state, [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15],
        );
    }

    let w0 = data.pop_front().unwrap();
    assert(data.is_empty(), 'thash_140: expected len = 35');
    let [d0, d1, d2, d3] = *w0;
    let [h0, h1, h2, h3, _, _, _, _] = hash_finalize_block(
        ref state, [d0, d1, d2, d3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    [h0, h1, h2, h3]
}

#[cfg(not(feature: "blake_hash"))]
pub fn thash_140(ctx: SpxCtx, address: @Address, mut data: Span<[u32; 4]>) -> HashOutput {
    let mut buffer = address.to_word_array();
    for item in data {
        buffer.append_u32_span(item.span());
    }
    thash_128s(ctx, address, buffer)
}

#[cfg(feature: "blake_hash")]
pub fn thash_56(ctx: SpxCtx, address: @Address, data: Span<[u32; 4]>) -> HashOutput {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = address.into_components();
    let data = data.try_into().expect('thash_btc_56: expected len = 14');
    let [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13] = (*data).unbox();
    let mut state = ctx.state_seeded;
    let [d0, d1, d2, d3] = w0;
    let [d4, d5, d6, d7] = w1;
    let [d8, d9, d10, d11] = w2;
    let [d12, d13, d14, d15] = w3;
    let [d16, d17, d18, d19] = w4;
    let [d20, d21, d22, d23] = w5;
    let [d24, d25, d26, d27] = w6;
    let [d28, d29, d30, d31] = w7;
    let [d32, d33, d34, d35] = w8;
    let [d36, d37, d38, d39] = w9;
    let [d40, d41, d42, d43] = w10;
    let [d44, d45, d46, d47] = w11;
    let [d48, d49, d50, d51] = w12;
    let [d52, d53, d54, d55] = w13;
    hash_update_block(ref state, [a0, a1, a2, a3, a4, a5, a6, a7, d0, d1, d2, d3, d4, d5, d6, d7]);
    hash_update_block(
        ref state, [d8, d9, d10, d11, d12, d13, d14, d15, d16, d17, d18, d19, d20, d21, d22, d23],
    );
    hash_update_block(
        ref state, [d24, d25, d26, d27, d28, d29, d30, d31, d32, d33, d34, d35, d36, d37, d38, d39],
    );
    let [h0, h1, h2, h3, _, _, _, _] = hash_finalize_block(
        ref state, [d40, d41, d42, d43, d44, d45, d46, d47, d48, d49, d50, d51, d52, d53, d54, d55],
    );
    [h0, h1, h2, h3]
}

#[cfg(not(feature: "blake_hash"))]
pub fn thash_56(ctx: SpxCtx, address: @Address, data: Span<[u32; 4]>) -> HashOutput {
    let mut buffer = address.to_word_array();
    for item in data {
        buffer.append_u32_span(item.span());
    }
    thash_128s(ctx, address, buffer)
}

/// Compute a truncated hash of the data.
pub fn thash_128s(ctx: SpxCtx, address: @Address, buffer: WordArray) -> HashOutput {
    let (words, last_word, last_word_len) = buffer.into_components();
    let [d0, d1, d2, d3, _, _, _, _] = hash_finalize(
        ctx.state_seeded, words, last_word, last_word_len,
    );
    [d0, d1, d2, d3]
}

/// Hash a message using selected hash function.
/// Returns the extended message digest of size SPX_DGST_BYTES as a [WordArray].
/// NOTE: this is not a generic implementation, rather a shortcut for 128s.
pub fn hash_message_128s(
    randomizer: HashOutput,
    pk_seed: HashOutput,
    pk_root: HashOutput,
    message: WordSpan,
    output_len: u32,
) -> WordArray {
    let mut data: Array<u32> = array![];
    data.append_span(randomizer.span());
    data.append_span(pk_seed.span());
    data.append_span(pk_root.span());

    let (msg_words, msg_last_word, msg_last_word_len) = message.into_components();
    data.append_span(msg_words);

    let mut state: HashState = Default::default();
    hash_init(ref state);

    // Compute the seed for XOF.
    let seed = hash_finalize(state, data, msg_last_word, msg_last_word_len);

    let mut xof_data: Array<u32> = array![];
    xof_data.append_span(randomizer.span());
    xof_data.append_span(pk_seed.span());
    xof_data.append_span(seed.span());
    xof_data.append(0); // MGF1 counter = 0

    // Apply MGF1 to the seed.
    let mut buffer = hash_finalize(state, xof_data.into(), 0, 0).span();

    // Construct the digest from the extended output.
    // NOTE: we haven't cleared the LSB of the last word, has to be handled correctly.
    let last_word = *buffer.pop_back().unwrap();

    // Construct the digest from the first 7 words (28 bits) and add 2 bytes from the last word.
    let res = WordArrayTrait::new(buffer.into(), last_word / 0x10000, 2);
    assert(res.byte_len() == output_len, 'Invalid extended digest length');
    res
}

/// Compute the root of a tree given the leaf and the authentication path.
pub fn compute_root(
    ctx: SpxCtx,
    address: @Address,
    leaf: HashOutput,
    mut auth_path: Span<HashOutput>,
    mut leaf_idx: u32,
    mut idx_offset: u32,
) -> HashOutput {
    let mut node = leaf;
    let mut i = 0;
    let mut address = address.clone();

    while let Some(hash_witness) = auth_path.pop_front() {
        let (q, r) = DivRem::div_rem(leaf_idx, 2);

        let (word0, word1) = if r == 0 {
            (node, *hash_witness)
        } else {
            (*hash_witness, node)
        };

        i += 1;
        leaf_idx = q;
        idx_offset /= 2;

        address.set_tree_height(i);
        address.set_tree_index(leaf_idx + idx_offset);

        node = thash_8(ctx, @address, word0, word1);
    }

    node
}

/// Serialize and deserialize HashOutput.
pub impl HashOutputSerde of Serde<HashOutput> {
    fn serialize(self: @HashOutput, ref output: Array<felt252>) {
        for elt in self.span() {
            output.append((*elt).into());
        }
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<HashOutput> {
        let h0: u32 = (*serialized.pop_front().expect('h0')).try_into().unwrap();
        let h1: u32 = (*serialized.pop_front().expect('h1')).try_into().unwrap();
        let h2: u32 = (*serialized.pop_front().expect('h2')).try_into().unwrap();
        let h3: u32 = (*serialized.pop_front().expect('h3')).try_into().unwrap();
        Some([h0, h1, h2, h3])
    }
}

#[cfg(or(test, feature: "debug"))]
pub fn to_hex(data: Span<u32>) -> ByteArray {
    let word_span = WordSpanTrait::new(data, 0, 0);
    crate::word_array::hex::words_to_hex(word_span)
}

#[cfg(and(test, not(feature: "blake_hash")))]
mod tests {
    use crate::word_array::hex::{words_from_hex, words_to_hex};
    use super::*;

    #[test]
    fn test_thash_128s() {
        let mut address: Address = Default::default();
        address.set_hypertree_layer(0);
        address.set_hypertree_addr(0x002f1d1de40b58e8);
        address.set_address_type(AddressType::FORSTREE);
        address.set_keypair(0x01f9);
        address.set_tree_height(0);
        address.set_tree_index(0x0000da49);

        //let mut address = words_from_hex("00 002f1d1de40b58e8 03 0000 01f9 0000 00000000 da49");
        //// address
        let (seed, _, _) = words_from_hex("d17096522c1d9de4e3c4c4e8659c1b86")
            .into_components(); // sk seed

        let mut buffer = address.to_word_array();
        buffer.append_u32_span(seed.span());
        let hash = thash_128s(Default::default(), @address, buffer);
        assert_eq!(hash, [2384795752, 2382117612, 736107028, 3412802428]);
    }

    #[test]
    fn test_thash_128s_2() {
        let address = AddressTrait::from_components(
            array![15967, 96104791, 956497920, 4849664, 0, 3481],
        );
        let message = [3845349652, 3980556369, 2345842860, 1383522053];
        let ctx = SpxCtx {
            state_seeded: HashState {
                h: (
                    3428492436,
                    489272603,
                    2537945631,
                    1304768729,
                    3790301264,
                    3396081315,
                    293230186,
                    253414835,
                ),
                byte_len: 64,
            },
        };
        let mut buffer = address.to_word_array();
        buffer.append_u32_span(message.span());
        let digest = thash_128s(ctx, @address, buffer);
        assert_eq!(digest, [629918136, 3883225718, 1150955665, 4167860371]);
    }

    #[test]
    fn test_hash_message_128s() {
        let message = words_from_hex(
            "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b",
        );
        let randomizer = [0xffffffff, 0x801de0fe, 0x12112e95, 0xf6f45d5b];
        let pk_seed = [0xbd1e2d02, 0x898d6567, 0xa1e03de5, 0x936fc5c9];
        let pk_root = [0x87b6c08a, 0xb0535371, 0x1dbf3a5c, 0x273e2aa8];
        let hash = hash_message_128s(randomizer, pk_seed, pk_root, message.span(), 30);
        let res = words_to_hex(hash.span());
        assert_eq!(res, "c7a141bc87731f09615dc587e6552c3699be19c948ec4ba9fd922626f153");
    }

    #[test]
    fn test_compute_root() {
        let mut address: Address = Default::default();
        let leaf = [189007633, 1442620421, 2505791230, 3002334628];
        let leaf_idx = 3308;
        let idx_offset = 53248;
        let auth_path = [
            [2317812994, 3624976225, 330492137, 1153586864],
            [2797063563, 589753341, 1224897870, 1223843493],
            [3847887728, 2208107316, 4272061531, 991551394],
            [3827109338, 236844412, 203585311, 778239555],
            [2435723185, 4277668986, 807919855, 1966534597],
            [1665196338, 1297211266, 2017105121, 2883830405],
            [26644628, 3698795534, 191361766, 4008495828],
            [3479434276, 1558485853, 136936866, 1914709136],
            [2501788134, 3276528649, 1086018752, 347301054],
            [2033991111, 680884808, 4015049346, 1026460870],
            [2828623812, 2435315588, 3344332178, 774210029],
            [1847957826, 195918516, 131309271, 2628527584],
        ];
        let root = compute_root(
            Default::default(), @address, leaf, auth_path.span(), leaf_idx, idx_offset,
        );
        assert_eq!(root, [3756782339, 3014392485, 518995719, 3556760177]);
    }

    #[test]
    fn test_initialize_hash_function() {
        let pk_seed = [1350675573, 3521007802, 3973994890, 3022267814];
        let ctx = initialize_hash_function(pk_seed);
        assert_eq!(
            ctx.state_seeded.h,
            (
                3428492436,
                489272603,
                2537945631,
                1304768729,
                3790301264,
                3396081315,
                293230186,
                253414835,
            ),
        );
        assert_eq!(ctx.state_seeded.byte_len, 64);
    }
}
