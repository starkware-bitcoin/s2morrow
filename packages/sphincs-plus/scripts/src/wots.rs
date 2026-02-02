use crate::context::SpxCtx;
use crate::utils::*;
use crate::thash::*;
use crate::address::*;
use crate::params::*;

// TODO clarify address expectations, and make them more uniform.
// TODO i.e. do we expect types to be set already?
// TODO and do we expect modifications or copies?

/// Computes the chaining function.
/// out and in have to be n-byte arrays.
/// Interprets in as start-th value of the chain.
/// addr has to contain the address of the chain.
pub fn gen_chain(
  out: &mut[u8], input: &[u8], start: u32, 
  steps: u32, ctx: &SpxCtx, addr: &mut[u32]
)
{
  out[..SPX_N].copy_from_slice(&input[..SPX_N]);

  // Iterate 'steps' calls to the hash function.
  let mut i = start;
  while i < (start+steps) && i < SPX_WOTS_W as u32 {
    set_hash_addr(addr, i);
    thash::<1>(out, None, ctx, addr);
    i += 1;
  }
}

/// base_w algorithm as described in draft.
/// Interprets an array of bytes as integers in base w.
/// This only works when log_w is a divisor of 8.
pub fn base_w(output: &mut[u32], out_len: u32, input: &[u8])
{
  let mut idx = 0;
  let mut out = 0;
  let mut total = 0u8;
  let mut bits = 0;

  for _ in 0..out_len {
    if bits == 0 {
      total = input[idx];
      idx += 1;
      bits += 8;
    }
    bits -= SPX_WOTS_LOGW;
    output[out] = (((total >> bits) & (SPX_WOTS_W - 1) as u8)) as u32;
    out += 1;
  }
}

/// Computes the WOTS+ checksum over a message (in base_w).
pub fn wots_checksum(csum_base_w: &mut[u32])
{
  let mut csum =  0u32;
  let mut csum_bytes = [0u8; (SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];

  // Compute checksum.
  for i in 0..SPX_WOTS_LEN1  {
    csum += SPX_WOTS_W as u32 - 1 - csum_base_w[i] as u32;
  }

  // Convert checksum to base_w.
  // Make sure expected empty zero bits are the least significant bits.
  csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
  let csum_sizeof = csum_bytes.len();
  ull_to_bytes(&mut csum_bytes, csum_sizeof, csum as u64);
  base_w(
    &mut csum_base_w[SPX_WOTS_LEN1..], SPX_WOTS_LEN2 as u32, &csum_bytes
  );
}

/// Takes a message and derives the matching chain lengths.
pub fn chain_lengths(lengths: &mut[u32], msg: &[u8])
{
  base_w(lengths, SPX_WOTS_LEN1 as u32, msg);
  wots_checksum(lengths);
}

/// Takes a WOTS signature and an n-byte message, computes a WOTS public key.
/// Writes the computed public key to 'pk'.
pub fn wots_pk_from_sig(
  pk: &mut[u8], sig: &[u8], msg: &[u8], ctx: &SpxCtx, addr: &mut[u32]
)
{
  let mut lengths = [0u32;  SPX_WOTS_LEN];
  chain_lengths(&mut lengths, msg);

  for i in 0..SPX_WOTS_LEN  {
    set_chain_addr(addr, i as u32);
    let steps = SPX_WOTS_W as u32 - 1 - lengths[i];
    gen_chain(&mut pk[i*SPX_N..], &sig[i*SPX_N..], lengths[i], steps, ctx, addr);
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  
  #[test]
  fn test_base_w() {
    let mut output = [0u32; SPX_WOTS_LEN1];
    let input: Vec<u8> = hex::decode("01020304050607081020304050607080").unwrap();
    base_w(&mut output, SPX_WOTS_LEN1 as u32, &input);
  }

  #[test]
  fn test_gen_chain() {
    let mut output = [0u8; SPX_N];
    let input: Vec<u8> = hex::decode("01020304050607081020304050607080").unwrap();
    gen_chain(&mut output, &input, 5, 10, &SpxCtx::default(), &mut [0u32; 8]);
  }

  #[test]
  fn test_gen_chain_2() {
    let mut output = [0u8; SPX_N];
    let input: Vec<u8> = hex::decode("61c5f0e5e2b5d692be00794f0561af0f").unwrap();
    gen_chain(&mut output, &input, 9, 6, &SpxCtx::default(), &mut [0u32; 8]);
  }

  #[test]
  fn test_wots_checksum() {
    let mut output = [0u32; SPX_WOTS_LEN1+4];
    let input: Vec<u8> = hex::decode("01020304050607081020304050607080").unwrap();
    base_w(&mut output, SPX_WOTS_LEN1 as u32, &input);
    wots_checksum(&mut output);
  }

  #[test]
  fn test_wots_pk_from_sig() {
    let mut pk = [0u8; 35*SPX_N];
    let sig = hex::decode("fd72a706890d214d9a8978ec33a673f47d7f0228a72bbd5b162c9d6a27953b8661c5f0e5e2b5d692be00794f0561af0f8e9d1f5befd58c53ad46e8d66021e7433cc8f50559ac7f3398ed16e4149a6e8983bfa16e496eb513e2e29c431d9ae18d549cad0c7b2ce9cce623a41c563182b2c334a2ec6230695ee418d79d7f820ce1a7842f30c9ab1c92711a4b7a5541993bbae5a141df4d8431acb81232a479d29e26004209caabcffb076e6f8997b40d3c49bbb7c48b4a17a1da9e6885511d761e67d7f9cb32f947913bb8b412ea25ff3451efe69ed5fc50a122eef12f02cd8f24f50276827d5c6c62eb124d7ff03d33e2431fdcdec49d09fbd5a1637cc2f4f5eed47ebac80abb4fab02ef79f6bb8b5f85f0935af14aa7bfb11a4fabb93460eac21e5505cb2a8184644bbf44a280f5fb1345f731acb2041e826fedbbce6ac146e200b6c5f1e3e4c68bcc59f08c0411f29097b4e18976058ec6a0f9fe9139539fd303073a1eb2c41a7e6d1425042b5c4d4c37dfc2d457cd63341a29f576ede11eff4bc45e84aea92797fd892ee3bfcfe17a510ce8b04a9164209d989262d7bc19ced3cefc403ab31d1699e070f7181d90961ebc964cdf5824276c78fd3f64d0f48f8b88c220b5123ccd60825f37aa4229e83b8ad78ebb531e2a32580e225b37c673594aa02528fe7b4295be5f675535ae295136113a7f172032d97d18b5cdf55a583de5c79d62feb83b376f60eb7a71e7ce93d42d4855f9cc580acfd791a74955cc3083fee72566de3c671c2fdd2c28ac8e").unwrap();
    let msg = hex::decode("1f9718421c7894a0b702df8a2cb77919").unwrap();
    wots_pk_from_sig(&mut pk, &sig, &msg, &SpxCtx::default(), &mut [0u32; 8]);
  }
}
