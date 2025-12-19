// SPDX-License-Identifier: MIT

use ml_kem::kem;
use ml_kem::ntt::{intt, ntt};
use ml_kem::params::{N, Q};

#[test]
fn ntt_roundtrip_property() {
    let mut input = array![];
    let mut i: u16 = 0;
    while i < N.try_into().unwrap() {
        input.append(i % Q);
        i += 1;
    }
    let f = input.span();
    let back = intt(ntt(f));
    assert_eq!(f, back);
}

#[test]
fn kem_shared_secret_matches() {
    let seed: u64 = 0xBEEF_F00D_CAFE_BABE;
    let (pk, sk) = kem::keygen(seed);
    let (ct, ss_enc) = kem::encapsulate(pk, seed + 7);
    let ss_dec = kem::decapsulate(sk, ct);
    assert(ss_enc.bytes == ss_dec.bytes, 'shared secret mismatch');
}

