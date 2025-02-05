#[cfg(test)]
mod test {
    use crate::merkle_tree::{Entry, MerkleTree, Node, Tree};
    use num_bigint::{BigUint, ToBigUint};
    use rand::Rng as _;

    const N_BYTES: usize = 8;

    #[test]
    fn test_merkle_tree() {
        // Create a new merkle tree from CSV
        let merkle_tree =
            MerkleTree::from_csv("/home/subhasishbehera/gnosis_inclusion/src/csv/entry_16.csv").unwrap();

        // Get root
        let root = merkle_tree.root();

        // Expect root hash to be different than 0
        assert!(root.hash != 0.into());

        // Expect depth to be 4
        assert!(*merkle_tree.depth() == 4_usize);

        // Get proof for entry 0
        let proof = merkle_tree.generate_proof(0).unwrap();

        // Verify proof
        assert!(merkle_tree.verify_proof(&proof));

        // Should generate different root hashes when changing the entry order
        let merkle_tree_2 =
            MerkleTree::from_csv("/home/subhasishbehera/gnosis_inclusion/src/csv/entry_16_switched_order.csv").unwrap();
        assert_ne!(root.hash, merkle_tree_2.root().hash);

        // Should create valid proof for each entry in the tree and verify it
        for i in 0..=15 {
            let proof = merkle_tree.generate_proof(i).unwrap();
            assert!(merkle_tree.verify_proof(&proof));
        }

        // Shouldn't create a proof for an entry that doesn't exist in the tree
        assert!(merkle_tree.generate_proof(16).is_err());

        // Shouldn't verify a proof with a wrong leaf
        let invalid_entry = Entry::new("InvalidUser".to_string());
        let mut proof_invalid_1 = proof.clone();
        proof_invalid_1.entry = invalid_entry;
        assert!(!merkle_tree.verify_proof(&proof_invalid_1));

        // Shouldn't verify a proof with a wrong root hash
        let mut proof_invalid_2 = proof.clone();
        proof_invalid_2.root.hash = 0.into();
        assert!(!merkle_tree.verify_proof(&proof_invalid_2));
    }

    // #[test]
    // fn test_update_merkle_tree_leaf() {
    //     let merkle_tree_1 =
    //         MerkleTree::<N_BYTES>::from_csv("../csv/entry_16.csv").unwrap();
    //
    //     let root_hash_1 = merkle_tree_1.root().hash;
    //
    //     // Create the second tree with a modified 7th entry
    //     let mut merkle_tree_2 =
    //         MerkleTree::<N_BYTES>::from_csv("../csv/entry_16.csv").unwrap();
    //
    //     let root_hash_2 = merkle_tree_2.root().hash;
    //     assert!(root_hash_1 != root_hash_2);
    //
    //     // Update the 7th leaf of the second tree so all entries match the first tree
    //     let new_root = merkle_tree_2
    //         .update_leaf("RkLzkDun")
    //         .unwrap();
    //     // The roots should match
    //     assert!(root_hash_1 == new_root.hash);
    // }

   // #[test]
    // fn test_update_invalid_merkle_tree_leaf() {
    //     let mut merkle_tree =
    //         MerkleTree::<N_BYTES>::from_csv_sorted("../csv/entry_16.csv").unwrap();
    //
    //     let new_root = merkle_tree.update_leaf("non_existing_user");
    //
    //     if let Err(e) = new_root {
    //         assert_eq!(e.to_string(), "Data not found");
    //     }
    // }

    #[test]
    fn test_sorted_merkle_tree() {
        let merkle_tree =
            MerkleTree::from_csv("/home/subhasishbehera/gnosis_inclusion/src/csv/entry_16.csv").unwrap();

        let old_root_hash = merkle_tree.root().hash;

        let sorted_merkle_tree =
            MerkleTree::from_csv_sorted("/home/subhasishbehera/gnosis_inclusion/src/csv/entry_16_switched_order.csv").unwrap();

        let new_root_hash = sorted_merkle_tree.root().hash;

        // The root hash should not be the same for sorted and unsorted trees
        assert!(old_root_hash != new_root_hash);
    }

    #[test]
    fn get_leaf_node_hash_preimage() {
        let merkle_tree =
            MerkleTree::from_csv("/home/subhasishbehera/gnosis_inclusion/src/csv/entry_16.csv").unwrap();

        // Generate a random number between 0 and 15
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..16);

        // Fetch leaf with index
        let leaf = merkle_tree.leaves()[index].clone();

        // Fetch the hash preimage of the leaf
        let hash_preimage = merkle_tree.get_leaf_node_hash_preimage(index).unwrap();

        let computed_leaf = Node::leaf_node_from_preimage(&hash_preimage);

        // The hash of the leaf should match the hash computed from the hash preimage
        assert_eq!(leaf.hash, computed_leaf.hash);
    }
}
