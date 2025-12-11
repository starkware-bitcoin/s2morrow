// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

pub mod address;
pub mod fors;
pub mod hasher;
pub mod params_128s;
pub mod sphincs;
pub mod word_array;
pub mod wots;
use crate::sphincs::{SphincsPublicKey, SphincsSignature};
use crate::word_array::{WordArray, WordArrayTrait};

#[derive(Drop, Serde, Default)]
pub struct Args {
    /// Sphincs+ public key.
    pub pk: SphincsPublicKey,
    /// Sphincs+ signature.
    pub sig: SphincsSignature,
    /// Message.
    pub message: WordArray,
}

#[executable]
fn main(args: Args) {
    let Args { pk, sig, message } = args;
    let res = sphincs::verify_128s(message.span(), sig, pk);
    check_result(res);
}

#[cfg(feature: "blake_hash")]
fn check_result(res: bool) { // TODO: generate a valid signature for blake_hash
}

#[cfg(not(feature: "blake_hash"))]
fn check_result(res: bool) {
    assert(res, 'invalid signature');
}
