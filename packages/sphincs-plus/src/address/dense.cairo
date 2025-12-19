// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! Address structure aligned for use with SHA2/Blake2s hash functions.
//! See https://www.di-mgt.com.au/pqc-09-fors-sig.html for layout details.

use crate::word_array::{WordArray, WordArrayTrait};
use super::AddressType;

/// Generic address layout:
///  0       4      8        12       16       20
/// [0 111] [1111] [1 2 xx] [3 3 xx] [x 4 55] [55]
///
/// WOTS address layout:
///  0       4      8        12       16       20
/// [0 111] [1111] [1 2 xx] [3 3 xx] [x 6 xx] [x 7]
///
/// Where:
/// 0. Hypertree layer (1 byte)
/// 1. Hypertree address (8 bytes)
/// 2. Address type (1 byte)
/// 3. Keypair hi/lo (2 bytes)
/// 4. Tree height (1 byte)
/// 5. Tree index (4 bytes)
/// 6. Wots chain address (1 byte)
/// 7. Wots hash address (1 byte)
#[derive(Drop, Default, Debug, Copy)]
pub struct Address {
    w0: u32, // layer, hypertree address
    w1: u32, // hypertree address 
    w2: u32, // hypertree address, address type
    w3: u32, // keypair high/low bytes
    w4: u32, // tree height | wots chain address
    w5: u32, // tree index | wots hash address (we use lower bytes)
    // Cached values
    w0_a: u32,
    w0_bcd: u32,
    w2_a: u32,
    w2_b: u32,
    w4_b: u32,
    w4_cd: u32,
}

#[generate_trait]
pub impl AddressImpl of AddressTrait {
    fn from_components(mut components: Array<u32>) -> Address {
        let w0 = components.pop_front().unwrap();
        let w1 = components.pop_front().unwrap();
        let w2 = components.pop_front().unwrap();
        let w3 = components.pop_front().unwrap();
        let w4 = components.pop_front().unwrap();
        let w5 = components.pop_front().unwrap();
        let (w0_a, w0_bcd) = DivRem::div_rem(w0, 0x1000000);
        let (w2_a, w2_b) = DivRem::div_rem(w2 / 0x10000, 0x100);
        let (w4_b, w4_cd) = DivRem::div_rem(w4 % 0x1000000, 0x10000);
        Address { w0, w1, w2, w3, w4, w5, w0_a, w0_bcd, w2_a, w2_b, w4_b, w4_cd }
    }

    fn set_hypertree_layer(ref self: Address, layer: u8) {
        self.w0_a = layer.into() * 0x1000000;
        self.w0 = self.w0_a + self.w0_bcd;
    }

    fn set_hypertree_addr(ref self: Address, tree_address: u64) {
        let (abc, defgh) = DivRem::div_rem(tree_address, 0x10000000000);
        let (defg, h) = DivRem::div_rem(defgh, 0x100);
        self.w0_bcd = abc.try_into().unwrap();
        self.w0 = self.w0_a + self.w0_bcd;
        self.w1 = defg.try_into().unwrap();
        self.w2_a = h.try_into().unwrap() * 0x1000000;
        // we don't care about the lowest 2 bytes (they are not used and set to zero)
        self.w2 = self.w2_a + self.w2_b;
    }

    fn set_address_type(ref self: Address, address_type: AddressType) {
        self.w2_b = address_type.into() * 0x10000;
        // we don't care about the lowest 2 bytes (they are not used and set to zero)
        self.w2 = self.w2_a + self.w2_b;
    }

    fn set_keypair(ref self: Address, keypair: u16) {
        // we don't care about the lowest 2 bytes (they are not used and set to zero)
        self.w3 = keypair.into() * 0x10000;
    }

    fn set_tree_height(ref self: Address, tree_height: u8) {
        self.w4_b = tree_height.into() * 0x10000;
        // we don't care about the highest byte (it is not used and set to zero)
        self.w4 = self.w4_b + self.w4_cd;
    }

    fn set_tree_index(ref self: Address, tree_index: u32) {
        let (ab, cd) = DivRem::div_rem(tree_index, 0x10000);
        self.w4_cd = ab;
        // we don't care about the highest byte (it is not used and set to zero)
        self.w4 = self.w4_b + self.w4_cd;
        // we use lower bytes for compatibility with [WordArray]
        self.w5 = cd;
    }

    fn set_wots_addr(ref self: Address, address: u32) {
        let (abc, wots_hash_addr) = DivRem::div_rem(address, 0x100);
        let (_, wots_chain_addr) = DivRem::div_rem(abc, 0x100);
        self.set_wots_chain_addr(wots_chain_addr.try_into().unwrap());
        self.set_wots_hash_addr(wots_hash_addr.try_into().unwrap());
    }

    fn set_wots_chain_addr(ref self: Address, chain_address: u8) {
        // In WOTS address other bytes are not used and set to zero.
        self.w4_b = chain_address.into() * 0x10000;
        // Other bytes are unused
        self.w4 = self.w4_b
    }

    fn set_wots_hash_addr(ref self: Address, hash_address: u8) {
        // In WOTS address other bytes are not used and set to zero.
        // We use lower bytes for compatibility with [WordArray]
        self.w5 = hash_address.into();
    }

    fn to_word_array(self: @Address) -> WordArray {
        WordArrayTrait::new(array![*self.w0, *self.w1, *self.w2, *self.w3, *self.w4], *self.w5, 2)
    }

    fn into_components(self: Address) -> (u32, u32, u32, u32, u32, u32, u32, u32) {
        (self.w0, self.w1, self.w2, self.w3, self.w4, self.w5, 0, 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::word_array::hex::words_to_hex;
    use super::*;

    #[test]
    fn test_fors_tree_address() {
        let mut address: Address = Default::default();
        address.set_hypertree_layer(0);
        address.set_hypertree_addr(14512697849565227);
        address.set_address_type(AddressType::FORSTREE);
        address.set_keypair(102);
        address.set_tree_height(0);
        address.set_tree_index(2765);
        let res = words_to_hex(address.to_word_array().span());
        let expected = "0000338f38c80e502b03000000660000000000000acd";
        assert_eq!(res, expected);
    }
}
