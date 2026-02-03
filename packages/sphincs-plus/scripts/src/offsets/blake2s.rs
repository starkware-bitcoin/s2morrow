/// Offsets of various fields in the sparse address structure when we use Blake2s as
/// the Sphincs+ hash function with Cairo-compatible sparse addressing.
/// Each field occupies a full u32 word (4 bytes).

pub const SPX_OFFSET_LAYER: usize = 0;       // Word 0: layer
pub const SPX_OFFSET_TREE_HI: usize = 1;     // Word 1: hypertree_addr_hi
pub const SPX_OFFSET_TREE_LO: usize = 2;     // Word 2: hypertree_addr_lo
pub const SPX_OFFSET_TYPE: usize = 3;        // Word 3: address_type
pub const SPX_OFFSET_KP_ADDR: usize = 4;     // Word 4: keypair
pub const SPX_OFFSET_TREE_HGT: usize = 5;    // Word 5: tree_height
pub const SPX_OFFSET_TREE_INDEX: usize = 6;  // Word 6: tree_index
pub const SPX_OFFSET_WOTS_ADDR: usize = 7;   // Word 7: wots_addr (chain_addr or hash_addr)
