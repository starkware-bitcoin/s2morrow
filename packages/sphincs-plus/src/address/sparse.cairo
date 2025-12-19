// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! Address structure aligned for use with SHA2/Blake2s hash functions.
//! See https://www.di-mgt.com.au/pqc-09-fors-sig.html for layout details.

use crate::word_array::{WordArray, WordArrayTrait};
use super::AddressType;

/// Simplified address layout
#[derive(Drop, Default, Debug, Copy)]
pub struct Address {
    layer: u32,
    hypertree_addr_hi: u32,
    hypertree_addr_lo: u32,
    address_type: u32,
    keypair: u32,
    tree_height: u32,
    tree_index: u32,
    wots_addr: u32,
}

#[generate_trait]
pub impl AddressImpl of AddressTrait {
    fn from_components(mut components: Array<u32>) -> Address {
        let layer = components.pop_front().unwrap();
        let hypertree_addr_hi = components.pop_front().unwrap();
        let hypertree_addr_lo = components.pop_front().unwrap();
        let address_type = components.pop_front().unwrap();
        let keypair = components.pop_front().unwrap();
        let tree_height = components.pop_front().unwrap();
        let tree_index = components.pop_front().unwrap();
        let wots_addr = components.pop_front().unwrap();
        Address {
            layer,
            hypertree_addr_hi,
            hypertree_addr_lo,
            address_type,
            keypair,
            tree_height,
            tree_index,
            wots_addr,
        }
    }

    fn set_hypertree_layer(ref self: Address, layer: u8) {
        self.layer = layer.into();
    }

    fn set_hypertree_addr(ref self: Address, tree_address: u64) {
        let (hi, lo) = DivRem::div_rem(tree_address, 0x100000000);
        self.hypertree_addr_hi = hi.try_into().unwrap();
        self.hypertree_addr_lo = lo.try_into().unwrap();
    }

    fn set_address_type(ref self: Address, address_type: AddressType) {
        self.address_type = address_type.into();
    }

    fn set_keypair(ref self: Address, keypair: u16) {
        self.keypair = keypair.into();
    }

    fn set_tree_height(ref self: Address, tree_height: u8) {
        self.tree_height = tree_height.into();
    }

    fn set_tree_index(ref self: Address, tree_index: u32) {
        self.tree_index = tree_index;
    }

    fn set_wots_addr(ref self: Address, address: u32) {
        self.wots_addr = address;
    }

    fn to_word_array(self: @Address) -> WordArray {
        WordArrayTrait::new(
            array![
                *self.layer, *self.hypertree_addr_hi, *self.hypertree_addr_lo, *self.address_type,
                *self.keypair, *self.tree_height, *self.tree_index, *self.wots_addr,
            ],
            0,
            0,
        )
    }

    fn into_components(self: Address) -> (u32, u32, u32, u32, u32, u32, u32, u32) {
        (
            self.layer,
            self.hypertree_addr_hi,
            self.hypertree_addr_lo,
            self.address_type,
            self.keypair,
            self.tree_height,
            self.tree_index,
            self.wots_addr,
        )
    }
}
