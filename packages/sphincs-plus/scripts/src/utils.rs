use crate::context::SpxCtx;
use crate::params::*;
use crate::thash::*;
use crate::address::*;

/// Converts the value of 'in' to 'outlen' bytes in big-endian byte order
#[cfg(not(feature = "blake2s"))]
pub fn ull_to_bytes(out: &mut[u8], outlen: usize, mut input: u64)
{
  // Iterate over out in decreasing order, for big-endianness.
  for i in (0..outlen).rev() {
    out[i] = (input & 0xff) as u8;
    input = input >> 8;
  }
}

pub fn u32_to_bytes(out: &mut[u8], input: u32)
{
  out[0] = (input >> 24) as u8;
  out[1] = (input >> 16) as u8;
  out[2] = (input >> 8) as u8;
  out[3] = input as u8;
}

/// Converts the inlen bytes in 'in' from big-endian byte order to an integer.
#[cfg(not(feature = "blake2s"))]
pub fn bytes_to_ull(input: &[u8], inlen: usize ) -> u64
{
  let mut retval = 0u64;
  for i in 0..inlen  {
    retval |= (input[i] as u64) << (8*(inlen - 1 - i));
  }
  return retval;
}

/// Computes a root node given a leaf and an auth path.
/// Expects address to be complete other than the tree_height and tree_index.
pub fn compute_root(
  root: &mut[u8], leaf: &[u8], mut leaf_idx: u32, mut idx_offset: u32,
  auth_path: &[u8], tree_height: u32, ctx: &SpxCtx, addr: &mut[u32; 8]
)
{
  let mut buffer = [0u8; 2 * SPX_N];
  let mut idx = 0usize;

  // If leaf_idx is odd (last bit = 1), current path element is a right child
  // and auth_path has to go left. Otherwise it is the other way around.
  if (leaf_idx & 1) != 0 {
    buffer[SPX_N..].copy_from_slice(&leaf[..SPX_N]);
    buffer[..SPX_N].copy_from_slice(&auth_path[..SPX_N]);
  }
  else {
    buffer[..SPX_N].copy_from_slice(&leaf[..SPX_N]);
    buffer[SPX_N..].copy_from_slice(&auth_path[..SPX_N]);
  }
  idx += SPX_N;

  //println!("auth path 0: {}", hex::encode(&auth_path[..SPX_N]));

  for i in 0..(tree_height - 1) {
    leaf_idx >>= 1;
    idx_offset >>= 1;
    // Set the address of the node we're creating.
    set_tree_height(addr, i + 1);
    set_tree_index(addr, leaf_idx + idx_offset);

    // Pick the right or left neighbour, depending on parity of the node.
    if (leaf_idx & 1) != 0 {
      let tmp_buffer = buffer.clone();
      thash::<2>(&mut buffer[SPX_N..], Some(&tmp_buffer), ctx, addr);
      buffer[..SPX_N].copy_from_slice(&auth_path[idx..][..SPX_N]);
  }
    else {
      thash::<2>(&mut buffer, None, ctx, addr);
      buffer[SPX_N..].copy_from_slice(&auth_path[idx..][..SPX_N]);
    }

    //println!("auth path {}: {}", i+1, hex::encode(&auth_path[idx..idx+SPX_N]));

    idx += SPX_N;
  }

  // The last iteration is exceptional; we do not copy an auth_path node.
  leaf_idx >>= 1;
  idx_offset >>= 1;
  set_tree_height(addr, tree_height);
  set_tree_index(addr, leaf_idx + idx_offset);
  thash::<2>(root, Some(&buffer), ctx, addr);
}

#[cfg(not(feature = "sparse_addr"))]
pub fn bytes_to_address(addr: &mut[u32], bytes: &[u8; 32])
{
  for i in 0..8 {
    let mut addr_i = [0u8; 4];
    addr_i.copy_from_slice(&bytes[i*4..][..4]);
    addr[i] = u32::from_be_bytes(addr_i);
  }
}

#[cfg(any(not(feature = "sparse_addr"), not(feature = "blake2s")))]
pub fn address_to_bytes(addr: &[u32]) -> [u8; 32]
{
  let mut out = [0u8; 32];
  for i in 0..8 {
    out[i*4..][..4].copy_from_slice(&addr[i].to_be_bytes()); // Endianness doesn't matter since we convert to bytes before hashing
  }
  out
}

/// Convert sparse address (8 u32 words) to bytes using little-endian ordering.
/// Used for Cairo-compatible Blake2s hashing.
/// The bytes are in LE format, matching how blake2 crate interprets them as u32 words.
#[cfg(feature = "sparse_addr")]
pub fn sparse_address_to_bytes(addr: &[u32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i*4..i*4+4].copy_from_slice(&addr[i].to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_compute_root() {
    let ctx = SpxCtx::default();

    let mut root = [0u8; SPX_N];
    let leaf = hex::decode("0b44071155fca405955b56feb2f3fda4").unwrap();
    let auth_path = hex::decode("8a270502d810bf6113b2e8e944c256b0a6b7cd8b2326ebfd4902754e48f25ea5e55a1b70839d0b34fea27c5b3b19dfa2e41d0dda0e1df57c0c22771f2e62fe43912e2fb1fef80c7a3027e0ef7536efc56340e1324d51df82783a94e1abe3c28501969094dc77240e0b67f2e6eeeccad4cf63f4245ce49b5d08297da272202490951e41e6c34bdc0940bb54c014b364be793c3dc728957a48ef50ca823d2e8cc6a8995fc49127f784c75675922e2581ed6e2599420bad7ab407d39ed79cac25e0").unwrap();

    let mut addr = [0u32; 8];
    #[cfg(not(feature = "sparse_addr"))]
    bytes_to_address(&mut addr, &[0u8; 32]);

    compute_root(&mut root, &leaf, 3308, 53248, &auth_path, 12, &ctx, &mut addr);
  }
}
