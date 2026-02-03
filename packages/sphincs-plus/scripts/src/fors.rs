use crate::context::SpxCtx;
use crate::utils::*;
use crate::utilsx1::*;
use crate::address::*;
use crate::params::*;
use crate::hash::*;
use crate::thash::*;

const STACK_LEN: usize = SPX_FORS_HEIGHT * SPX_N;

pub fn fors_gen_sk(sk: &mut[u8], ctx: &SpxCtx, fors_leaf_addr: &mut[u32])
{
  prf_addr(sk, ctx, fors_leaf_addr);
}

pub fn fors_sk_to_leaf(
  leaf: &mut[u8], sk: &[u8], ctx: &SpxCtx, fors_leaf_addr: &mut[u32]
)
{
  thash::<1>(leaf, Some(sk), ctx, fors_leaf_addr);
}

#[derive(Clone, Copy)]
pub struct ForsGenLeafInfo {
  pub leaf_addrx: [u32; 8]
}

impl Default for ForsGenLeafInfo {
  fn default() -> Self {
    Self { leaf_addrx: [0u32; 8] }
  }
}

pub fn fors_gen_leafx1(
  leaf: &mut[u8], ctx: &SpxCtx, addr_idx: u32, info: &mut ForsGenLeafInfo
)
{
  let mut fors_leaf_addr = info.leaf_addrx;
  
  set_tree_index(&mut fors_leaf_addr, addr_idx);
  set_type(&mut fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
  fors_gen_sk(leaf, ctx, &mut fors_leaf_addr);
  set_type(&mut fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
  thash::<1>(leaf, None, ctx, &fors_leaf_addr);
}


/// Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
/// Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
/// Assumes indices has space for SPX_FORS_TREES integers.
#[cfg(not(feature = "blake2s"))]
pub fn message_to_indices(indices: &mut[u32], m: &[u8])
{
  let mut offset = 0;

  for i in 0..SPX_FORS_TREES  {
    indices[i] = 0;
    for j in 0..SPX_FORS_HEIGHT  {
      indices[i] ^= (((m[offset >> 3] >> (offset & 0x7)) & 0x1) as u32) << j;
      offset += 1;
    }
  }
}

/// Cairo-compatible message_to_indices for Blake2s mode.
/// Processes mhash as u32 words with big-endian byte order within each word,
/// matching Cairo's message_to_indices_128s.
#[cfg(feature = "blake2s")]
pub fn message_to_indices(indices: &mut[u32], m: &[u8])
{
    let mut idx = 0;
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;

    // Process 5 full words (20 bytes) + 1 byte
    let num_full_words = SPX_FORS_MSG_BYTES / 4;  // 5 for 21 bytes
    let remaining_bytes = SPX_FORS_MSG_BYTES % 4;  // 1 for 21 bytes

    for word_idx in 0..num_full_words {
        // Read word as little-endian (how it's stored in memory)
        // then interpret bytes in big-endian order (how Cairo does it)
        let word = u32::from_le_bytes(m[word_idx*4..word_idx*4+4].try_into().unwrap());

        // Decompose word into bytes in big-endian order: [ab, cd, ef, gh]
        let ab = (word >> 24) & 0xFF;
        let cd = (word >> 16) & 0xFF;
        let ef = (word >> 8) & 0xFF;
        let gh = word & 0xFF;

        if acc_bits == 0 {
            // Pattern: [dab efc, gh]
            let c = cd >> 4;
            let d = cd & 0xF;
            indices[idx] = d * 0x100 + ab; idx += 1;
            indices[idx] = ef * 0x10 + c; idx += 1;
            acc = gh;
            acc_bits = 8;
        } else if acc_bits == 8 {
            // Pattern: [bxx cda hef, g]
            let a = ab >> 4;
            let b = ab & 0xF;
            let g = gh >> 4;
            let h = gh & 0xF;
            indices[idx] = b * 0x100 + acc; idx += 1;
            indices[idx] = cd * 0x10 + a; idx += 1;
            indices[idx] = h * 0x100 + ef; idx += 1;
            acc = g;
            acc_bits = 4;
        } else if acc_bits == 4 {
            // Pattern: [abx fcd ghe]
            let e = ef >> 4;
            let f = ef & 0xF;
            indices[idx] = ab * 0x10 + acc; idx += 1;
            indices[idx] = f * 0x100 + cd; idx += 1;
            indices[idx] = gh * 0x10 + e; idx += 1;
            acc = 0;
            acc_bits = 0;
        }
    }

    // Process remaining byte(s)
    if remaining_bytes == 1 {
        // The mhash is now constructed correctly in hash_message:
        // m[20] contains the MSB of word[5] from the original hash output
        let last_byte = m[num_full_words * 4] as u32;  // m[20]

        assert_eq!(acc_bits, 4);
        indices[idx] = last_byte * 0x10 + acc;
    }
}

/// Signs a message m, deriving the secret key from sk_seed and the FTS address.
/// Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
pub fn fors_sign(
  sig: &mut[u8], pk: &mut[u8], m: &[u8], ctx: &SpxCtx, fors_addr: &mut[u32]
)
{
  let mut indices = [0u32; SPX_FORS_TREES];
  let mut roots = [0u8; SPX_FORS_TREES * SPX_N];
  let mut fors_tree_addr = [0u32; 8];
  let mut fors_info = ForsGenLeafInfo::default();
  let mut fors_pk_addr = [0u32; 8];
  let mut idx_offset;

  copy_keypair_addr(&mut fors_tree_addr, fors_addr);
  copy_keypair_addr(&mut fors_info.leaf_addrx, fors_addr);

  copy_keypair_addr(&mut fors_pk_addr, fors_addr);
  set_type(&mut fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

  message_to_indices(&mut indices, m);
  let mut idx = 0usize;
  for i in 0..SPX_FORS_TREES  {
    idx_offset = (i * (1 << SPX_FORS_HEIGHT)) as u32;

    set_tree_height(&mut fors_tree_addr, 0);
    set_tree_index(&mut fors_tree_addr, indices[i] + idx_offset);
    set_type(&mut fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

    // Include the secret key part that produces the selected leaf node. /// 
    fors_gen_sk(&mut sig[idx..], ctx, &mut fors_tree_addr);
    set_type(&mut fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    idx += SPX_N;

    // Compute the authentication path for this leaf node. /// 
      
    fors_treehashx1::<SPX_FORS_HEIGHT, STACK_LEN>(
      &mut roots[i*SPX_N..], &mut sig[idx..], &ctx, indices[i], 
      idx_offset,&mut fors_tree_addr, &mut fors_info
    );

    idx += SPX_N * SPX_FORS_HEIGHT;
  }
  // Hash horizontally across all tree roots to derive the public key. /// 
  thash::<SPX_FORS_TREES>(pk, Some(&roots), ctx, &fors_pk_addr);
}

/// Derives the FORS public key from a signature.
/// This can be used for verification by comparing to a known public key, or to
/// subsequently verify a signature on the derived public key. The latter is the
/// typical use-case when used as an FTS below an OTS in a hypertree.
/// Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
pub fn fors_pk_from_sig(
  pk: &mut[u8], sig: &[u8], m: &[u8], ctx: &SpxCtx, fors_addr: &mut[u32]
)
{
  let mut indices = [0u32; SPX_FORS_TREES];
  let mut roots = [0u8; SPX_FORS_TREES * SPX_N];
  let mut leaf = [0u8; SPX_N];
  let mut fors_tree_addr = [0u32; 8];
  let mut fors_pk_addr = [0u32; 8];
  let mut idx_offset;

  copy_keypair_addr(&mut fors_tree_addr, fors_addr);
  copy_keypair_addr(&mut fors_pk_addr, fors_addr);

  set_type(&mut fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
  set_type(&mut fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

  message_to_indices(&mut indices, m);

  let mut idx = 0usize;
  for i in 0..SPX_FORS_TREES  {
      idx_offset = i as u32 * (1 << SPX_FORS_HEIGHT as u32);

      set_tree_height(&mut fors_tree_addr, 0);
      set_tree_index(&mut fors_tree_addr, indices[i] + idx_offset);

      // Derive the leaf from the included secret key part.
      fors_sk_to_leaf(&mut leaf, &sig[idx..], ctx, &mut fors_tree_addr);
      idx += SPX_N;

      // Derive the corresponding root node of this tree.
      compute_root(
        &mut roots[i*SPX_N..], &leaf, indices[i], idx_offset,
        &sig[idx..], SPX_FORS_HEIGHT as u32, ctx, &mut fors_tree_addr
      );

      idx += SPX_N * SPX_FORS_HEIGHT;
  }

  // Hash horizontally across all tree roots to derive the public key.
  thash::<SPX_FORS_TREES>(pk, Some(&roots), ctx, &fors_pk_addr);
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_fors_sk_to_leaf() {
    let ctx = SpxCtx::default();
    let sk = hex::decode("d17096522c1d9de4e3c4c4e8659c1b86").unwrap();
    let mut fors_leaf_addr = [12061, 501484376, 3892510720, 33095680, 0, 3662217216, 0, 0];
    let mut leaf = [0u8; SPX_N];
    fors_sk_to_leaf(&mut leaf, &sk, &ctx, &mut fors_leaf_addr);
  }
}
