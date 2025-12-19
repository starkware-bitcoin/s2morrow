// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! WOTS+ one-time signature scheme.
//! See https://research.dorahacks.io/2022/10/26/hash-based-post-quantum-signatures-1/ for an
//! overview.
//! See also https://www.di-mgt.com.au/pqc-03-winternitz.html

use core::traits::DivRem;
use crate::address::{Address, AddressTrait};
use crate::hasher::{HashOutput, HashOutputSerde, SpxCtx, thash_4};
use crate::params_128s::SPX_WOTS_LEN;

/// WOTS+ signature: array of partially hashed private keys.
pub type WotsSignature = [HashOutput; SPX_WOTS_LEN];

pub impl WotsSignatureSerde of Serde<WotsSignature> {
    fn serialize(self: @WotsSignature, ref output: Array<felt252>) {
        let mut iter = self.span();
        while let Some(elt) = iter.pop_front() {
            HashOutputSerde::serialize(elt, ref output);
        }
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<WotsSignature> {
        let mut arr = array![];
        for i in 0..SPX_WOTS_LEN {
            let elt = HashOutputSerde::deserialize(ref serialized).expect(i.into());
            arr.append(elt);
        }
        let res: @Box<[HashOutput; SPX_WOTS_LEN]> = arr.span().try_into().unwrap();
        Some(res.unbox())
    }
}

pub impl WotsSignatureDefault of Default<WotsSignature> {
    fn default() -> WotsSignature {
        [Default::default(); SPX_WOTS_LEN]
    }
}

/// Takes a WOTS signature and an n-byte message, computes a WOTS public key.
pub fn wots_pk_from_sig(
    ctx: SpxCtx, sig: WotsSignature, message: HashOutput, address: @Address,
) -> Array<[u32; 4]> {
    let mut lengths = base_w_128s(message.span());
    add_checksum_128s(ref lengths);

    let mut sig_iter = sig.span();
    let mut lengths_iter = lengths.span();
    // Use 2nd LSB for chain id
    let mut chain_idx: u32 = 0;
    let mut pk = array![];

    while let Some(len) = lengths_iter.pop_front() {
        let sk = sig_iter.pop_front().unwrap();
        let chain_pk = chain_hash_128s(ctx, *sk, *len, address, chain_idx);
        pk.append(chain_pk);

        chain_idx += 0x100;
    }

    pk
}

/// Computes the WOTS+ checksum over a message (in base_w) and appends it to the end.
pub fn add_checksum_128s(ref message_w: Array<u32>) {
    let mut csum: u32 = 0;

    let mut msg_iter = message_w.span();
    while let Some(elt_w) = msg_iter.pop_front() {
        csum += 15 - *elt_w; // SPX_WOTS_W - 1 - elt_w
    }

    // Convert checksum to base_w.
    // For 128s the size of checksum is 12 bits.
    // We shift the checksum left by 4 bits to make sure expected empty zero bits are the least
    // significant bits.
    let (e, fg) = DivRem::div_rem(csum, 0x100);
    let (f, g) = DivRem::div_rem(fg, 0x10);
    message_w.append_span(array![e, f, g].span());
}

/// Compute the H^{steps}(input) hash chain given the chain length (start) and return the last
/// digest.
pub fn chain_hash_128s(
    ctx: SpxCtx, input: HashOutput, length: u32, address: @Address, chain_idx: u32,
) -> HashOutput {
    if length == 15 {
        return input;
    }

    let mut wots_addr = address.clone();
    wots_addr.set_wots_addr(chain_idx + length);

    let mut output = thash_4(ctx, @wots_addr, input);

    for i in length + 1..15 { // SPX_WOTS_W - 1
        wots_addr.set_wots_addr(chain_idx + i);
        output = thash_4(ctx, @wots_addr, output);
    }
    output
}

/// Split input into chunks of 4 bits each for 128s parameter set (W=16).
pub fn base_w_128s(mut input: Span<u32>) -> Array<u32> {
    let mut output = array![];
    while let Some(word) = input.pop_front() {
        // Interpret 32-bit word as [ab cd ef gh]
        let (a, bcdefgh) = DivRem::div_rem(*word, 0x10000000);
        let (b, cdefgh) = DivRem::div_rem(bcdefgh, 0x1000000);
        let (c, defgh) = DivRem::div_rem(cdefgh, 0x100000);
        let (d, efgh) = DivRem::div_rem(defgh, 0x10000);
        let (e, fgh) = DivRem::div_rem(efgh, 0x1000);
        let (f, gh) = DivRem::div_rem(fgh, 0x100);
        let (g, h) = DivRem::div_rem(gh, 0x10);
        output.append_span(array![a, b, c, d, e, f, g, h].span());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_w_128s() {
        let input = array![0x01020304, 0x05060708, 0x10203040, 0x50607080];
        let output = base_w_128s(input.span());
        assert_eq!(
            output,
            array![
                0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0,
                7, 0, 8, 0,
            ],
        );
    }

    #[test]
    fn test_chain_hash() {
        let input = [0x01020304, 0x05060708, 0x10203040, 0x50607080];
        let mut address = Default::default();
        let output = chain_hash_128s(Default::default(), input, 5, @address, 0);
        assert_eq!(output, [0x8ae6cda7, 0xa098be21, 0x7c81bb4e, 0x860dd304]);
    }

    #[test]
    fn test_chain_hash_2() {
        let input = [2105475624, 2804661595, 372022634, 664091526];
        let mut address = Default::default();
        let output = chain_hash_128s(Default::default(), input, 15, @address, 0);
        assert_eq!(output, [2105475624, 2804661595, 372022634, 664091526]);
    }

    #[test]
    fn test_chain_hash_3() {
        let input = [1640362213, 3803567762, 3187702095, 90287887];
        let mut address = Default::default();
        let output = chain_hash_128s(Default::default(), input, 9, @address, 0);
        assert_eq!(output, [3700563191, 1880524724, 4147099568, 1051379323]);
    }

    #[test]
    fn test_add_checksum() {
        let input = array![0x01020304, 0x05060708, 0x10203040, 0x50607080];
        let mut output = base_w_128s(input.span());
        add_checksum_128s(ref output);
        assert_eq!(
            output,
            array![
                0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0,
                7, 0, 8, 0, 1, 9, 8,
            ],
        );
    }

    #[test]
    fn test_wots_pk_from_sig() {
        let message = [529995842, 477664416, 3070418826, 750221593];
        let sig = [
            [4252149510, 2299339085, 2592700652, 866546676],
            [2105475624, 2804661595, 372022634, 664091526],
            [1640362213, 3803567762, 3187702095, 90287887],
            [2392661851, 4023749715, 2907105494, 1612834627],
            [1019802885, 1504476979, 2565674724, 345665161],
            [2210373998, 1231992083, 3806501955, 496689549],
            [1419554060, 2066541004, 3861095452, 1446085298],
            [3275006700, 1647339870, 3826833309, 2139229409],
            [2810457904, 3383434386, 1897548666, 1430362427],
            [3135611201, 3746399281, 2897744434, 2759447198],
            [637551113, 3400257531, 124678025, 2545159484],
            [1237039044, 2336888737, 3667814533, 1360885278],
            [1742207435, 855197585, 1001960466, 3928358708],
            [1374676638, 3590082721, 586084655, 47025956],
            [4110579330, 2103209058, 3943845247, 4030542818],
            [1126161630, 3298626043, 3584123772, 3270833646],
            [3565075144, 180047787, 49248758, 3146473349],
            [4036188913, 1252507569, 441428921, 878766786],
            [508888523, 713131108, 1270826146, 2163604243],
            [1173828012, 2986614402, 1877851086, 1791051490],
            [11978225, 3823421067, 3428446348, 68285072],
            [2545213833, 1980075718, 2700738193, 961781715],
            [50805278, 2999196286, 1830036740, 727469388],
            [937411284, 1473078068, 438957430, 3990953727],
            [1271160452, 2930321303, 4253626083, 3218071930],
            [1359800496, 1251042336, 2644021858, 3619428814],
            [3553557568, 984816918, 2581623031, 404590742],
            [515675724, 3747095591, 1819868479, 1691415695],
            [2340995616, 3037871309, 1619156791, 2856462824],
            [998954894, 3142786602, 844631586, 1530381939],
            [1498062885, 687766338, 2512281447, 1429581353],
            [1362497850, 2132222002, 3648854197, 3455408728],
            [1038469021, 1660860475, 930046187, 2054285262],
            [2480155976, 1442434136, 181393297, 2806601164],
            [813956839, 627498556, 1729900509, 740863118],
        ];
        let pk = wots_pk_from_sig(Default::default(), sig, message, Default::default());
        let expected: Array<[u32; 4]> = array![
            [4280157821, 1513564328, 2473981278, 1876372688],
            [2105475624, 2804661595, 372022634, 664091526],
            [4027238432, 3872223822, 221106114, 524906229],
            [3752097775, 3146560125, 1879590184, 1636129964],
            [1329032692, 1000072347, 3970031369, 3872965792],
            [2851349356, 1936208600, 4116230018, 1903880740],
            [2354241252, 2704498587, 2531552482, 3396990295],
            [3059900203, 2253426115, 346500790, 1971047600],
            [1976751202, 1558561151, 2411291362, 3037858944],
            [132968461, 3575066386, 681930895, 3305151734],
            [3501974190, 1880654097, 3092213966, 779706411],
            [2735033803, 2191385983, 4067752648, 224793655],
            [1049788647, 3648462208, 1958295452, 3903679462],
            [1872779743, 1742982837, 2642993569, 1390176031],
            [2883706984, 2246101291, 2493097667, 847341441],
            [3420010809, 3157666235, 2622558776, 3462711826],
            [1129806005, 2397760597, 3130810852, 3502719843],
            [1789548901, 2313604717, 3151691158, 2545361183],
            [206247809, 265279999, 1583259327, 1865531287],
            [321117893, 852595799, 560662171, 3090666296],
            [3391532313, 3120352875, 1311959318, 1580968828],
            [2545213833, 1980075718, 2700738193, 961781715],
            [2466583066, 3293382051, 3386751889, 300355772],
            [1428415600, 3099647130, 1578840000, 3241854699],
            [4010338708, 3087882097, 2264660391, 3219392681],
            [1357253572, 3859712449, 3992315401, 1294093020],
            [530094087, 1229019980, 818672529, 3160378578],
            [3713034739, 208429519, 2762526678, 3510982306],
            [1953661473, 3878873515, 262957853, 2271901417],
            [3369540373, 4292115841, 2217881177, 640391144],
            [585932212, 726570137, 2030731473, 3459932845],
            [791428494, 3675324530, 3955694332, 220871188],
            [1568371551, 1526534631, 1313077632, 1000364894],
            [3919277696, 3303850749, 3847800427, 2719146028],
            [3796859057, 3744444374, 3993582049, 3262321084],
        ];
        assert_eq!(pk, expected);
    }
}
