// SPDX-License-Identifier: MIT

pub mod kem;
pub mod ntt;
pub mod ntt_constants;
pub mod params;
pub mod poly;
pub mod sampler;
pub mod zq;

#[derive(Drop, Serde)]
struct Args {
    seed: u64,
}

#[executable]
fn main(args: Args) {
    let (pk, sk) = kem::keygen(args.seed);
    let (ct, ss) = kem::encapsulate(pk, args.seed + 1);
    let ss2 = kem::decapsulate(sk, ct);
    assert(ss.bytes == ss2.bytes, 'shared secret mismatch');
    println!("shared_secret: {:?}", ss.bytes);
}

