// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

pub mod falcon;
pub mod ntt;
pub mod ntt_constants;
pub mod zq;

#[derive(Drop, Serde)]
struct Args {
    attestations: Array<Attestation>,
    n: u32,
}

#[derive(Drop, Serde)]
struct Attestation {
    s1: Span<u16>,
    pk: Span<u16>,
    msg_point: Span<u16>,
}

#[executable]
fn main(args: Args) {
    let Args { attestations, n } = args;
    println!("Verifying {} signatures", attestations.len());

    for attestation in attestations.span() {
        falcon::verify_uncompressed::<
            512,
        >(*attestation.s1, *attestation.pk, *attestation.msg_point, n)
            .expect('Invalid signature');
    }
    println!("OK");
}
