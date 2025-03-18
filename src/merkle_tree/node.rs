use crate::chips::poseidon::poseidon_spec::PoseidonSpec;
use crate::merkle_tree::utils::big_uint_to_fp;
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use num_bigint::BigUint;
use crate::poseidon_native::hasher::{poseidon_bn254_5x5::Params};
use crate::poseidon_native::PoseidonNative;

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub hash: Fp,
}

impl Node {
    /// Builds a leaf-level node of the Merkle Tree
    /// The leaf node hash is `H(data)`, where data could be any input converted to `Fp`.
    pub fn leaf(data: &BigUint) -> Node {
        //let hash_input = [big_uint_to_fp(data)];
        let inputs = [
            big_uint_to_fp(data),
            Fp::zero(),
            Fp::zero(),
            Fp::zero(),
            Fp::zero()
        ];
        let poseidon = PoseidonNative::<5, Params>::new(inputs);
        let permuted = poseidon.permute();

        Node { hash: permuted[0] }
    }
    /// Builds a "middle" (non-leaf-level) node of the Merkle Tree
    /// The middle node hash is `H(LeftChild.hash, RightChild.hash)`.
    pub fn middle(left_child: &Node, right_child: &Node) -> Node {
        // let hash_preimage = [left_child.hash, right_child.hash];
        // let hash = poseidon::Hash::<Fp, PoseidonSpec, ConstantLength<2>, 2, 1>::init()
        //     .hash(hash_preimage.clone());
        // Node { hash }
        let inputs = [
            left_child.hash,
            right_child.hash,
            Fp::zero(),
            Fp::zero(),
            Fp::zero()
        ];

        let poseidon = PoseidonNative::<5, Params>::new(inputs);
        let permuted = poseidon.permute();

        Node { hash: permuted[0] }
    }
    /// Returns an empty node where the hash is 0
    pub fn init_empty() -> Node {
        Node { hash: Fp::zero() }
    }

    pub fn leaf_node_from_preimage(preimage: &[Fp; 1]) -> Node
    {
        // let hash =
        //     poseidon::Hash::<Fp, PoseidonSpec, ConstantLength< 1 >, 2, 1>::init()
        //         .hash(preimage.clone());
        // Node {
        //     hash,
        //
        // }
        let inputs = [preimage[0], Fp::zero(), Fp::zero(), Fp::zero(), Fp::zero()];

        let hasher = PoseidonNative::<5, Params>::new(inputs);
        // let poseidon = PoseidonNative::<5, Params>::new(inputs);
        let permuted = hasher.permute();

        Node { hash: permuted[0] }
    }

    /// Helper function to create a leaf node from a preimage (used in proof verification).
    // pub fn leaf_node_from_preimage(preimage: &Fp) -> Node {
    //     let hash = poseidon::Hash::<Fp, PoseidonSpec, ConstantLength<1>, 2, 1>::init()
    //         .hash([*preimage]);
    //     Node { hash }
    // }

    /// Helper function to create a middle node from a preimage of two child hashes
    /// (used in proof verification).
    pub fn middle_node_from_preimage(preimage: &[Fp; 2]) -> Node {
        // let hash = poseidon::Hash::<Fp, PoseidonSpec, ConstantLength<2>, 2, 1>::init()
        //     .hash(preimage.clone());
        // Node { hash }
        let mut inputs = [Fp::zero(); 5];
        for (i, &val) in preimage.iter().enumerate() {
            inputs[i] = val;
        }

        let hasher = PoseidonNative::< 5,Params>::new(inputs);
        let hashed = hasher.permute();

        Self {
            hash: hashed[0],
        }
    }
}
#[test]
fn test_middle_node_hash() {
    let left = Node { hash: Fp::from(1u64) };
    let right = Node { hash: Fp::from(2u64) };

    let middle = Node::middle(&left, &right);

    println!("Computed Middle Node Hash: {:?}", middle.hash);
}
