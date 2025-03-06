pub mod node;
pub mod tree;
pub mod utils;
pub mod entry;
pub mod mt;
pub mod tests;
use halo2_proofs::halo2curves::bn256::Fr as Fp;

/// A struct representing a Merkle Proof.
///
/// Fields:
/// * `entry`: The entry for which the proof is generated
/// * `root`: The root of the Merkle Sum Tree
/// * `sibling_leaf_node_hash_preimage`: The hash preimage of the sibling leaf node. The hash preimage is equal to `[sibling_username, sibling.balance[0], sibling.balance[1], ... sibling.balance[N_CURRENCIES - 1]]`
/// * `sibling_middle_node_hash_preimages`: The hash preimages of the sibling middle nodes. The hash preimage is equal to `[sibling_left_child.balance[0] + sibling_right_child.balance[0], sibling_left_child.balance[1] + sibling_right_child.balance[1], ..., sibling_left_child.balance[N_CURRENCIES - 1] + sibling_right_child.balance[N_CURRENCIES - 1], sibling_left_child.hash, sibling_right_child.hash]`
#[derive(Clone, Debug)]
pub struct MerkleProof
{
    pub entry: Entry,
    pub root: Node,
    pub sibling_leaf_node_hash_preimage: [Fp; 1],
    pub sibling_middle_node_hash_preimages: Vec<[Fp; 2]>,
    pub path_indices: Vec<Fp>,
}
use std::fmt;

// impl fmt::Debug for MerkleProof {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(
//             f,
//             "MerkleProof {{ entry: {:?}, root: {:?}, sibling_leaf_node_hash_preimage: {:?}, sibling_middle_node_hash_preimages: {:?}, path_indices: {:?} }}",
//             self.entry, self.root, self.sibling_leaf_node_hash_preimage, self.sibling_middle_node_hash_preimages, self.path_indices
//         )
//     }
// }
pub use entry::Entry;
pub use mt::MerkleTree;
pub use node::Node;
pub use tree::Tree;
