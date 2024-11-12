use crate::merkle_tree::node::Node;
use ethers::utils::keccak256;
use num_bigint::BigUint;

/// An entry in the Merkle Sum Tree from the database of the CEX.
/// It contains the username and the balances of the user.
#[derive(Clone, Debug, std::cmp::PartialEq)]
pub struct Entry {
    hashed_data: BigUint,
    data: String,
}

impl Entry {
   /// Creates a new `Entry` with the given data.
    /// Uses `keccak256` to hash the data string into `hashed_data`.
    pub fn new(data: String) -> Self {
        // Hashing the data with `keccak256` for collision resistance
        let hashed_data: BigUint = BigUint::from_bytes_be(&keccak256(data.as_bytes()));
        Entry {
            hashed_data,
            data,
        }
    }

   /// Returns a zero entry where the data is "0" and the hashed data is zero.
   pub fn zero_entry() -> Self {
    Entry {
        hashed_data: BigUint::from(0u32),
        data: "0".to_string(),
    }
}

     /// Computes the Merkle tree leaf node for this entry.
     pub fn compute_leaf(&self) -> Node {
        Node::leaf(&self.hashed_data)
    }
    pub fn data_as_big_uint(&self) -> &BigUint {
        &self.hashed_data
    }

    pub fn data(&self) -> &str {
        &self.data
    }
}
