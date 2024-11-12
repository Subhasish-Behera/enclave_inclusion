use crate::merkle_tree::utils::big_uint_to_fp;
use crate::merkle_tree::{Entry, MerkleProof, Node};
use halo2_proofs::halo2curves::bn256::Fr as Fp;

/// A trait representing the basic operations for a Merkle-like Tree.
pub trait Tree {
    /// Returns a reference to the root node.
    fn root(&self) -> &Node;

    /// Returns the depth of the tree.
    fn depth(&self) -> &usize;

    /// Returns a slice of the nodes.
    fn nodes(&self) -> &[Vec<Node>];

    // /// Returns the cryptocurrencies whose balances are in the tree. The order of cryptocurrencies and balances is supposed to agree for all the entries.
    // fn cryptocurrencies(&self) -> &[Cryptocurrency];

    fn get_entry(&self, index: usize) -> &Entry;

    /// Returns the hash preimage of a middle node.
    fn get_middle_node_hash_preimage(
        &self,
        level: usize,
        index: usize,
    ) -> Result<[Fp; 2], Box<dyn std::error::Error>>
    {
        if level == 0 || level > *self.depth() {
            return Err(Box::from("Invalid depth"));
        }

        self.nodes()
            .get(level)
            .and_then(|layer| layer.get(index))
            .ok_or_else(|| Box::<dyn std::error::Error>::from("Node not found"))?;

        // Assuming the left and right children are stored in order
        let left_child = &self.nodes()[level - 1][2 * index];
        let right_child = &self.nodes()[level - 1][2 * index + 1];

        // Constructing preimage
        let mut preimage = [left_child.hash, right_child.hash];

        Ok(preimage)
    }

    /// Returns the hash preimage of a leaf node.
    fn get_leaf_node_hash_preimage(
        &self,
        index: usize,
    ) -> Result<[Fp;1], Box<dyn std::error::Error>>
    {
        // Fetch entry corresponding to index
        let entry = self.get_entry(index);

        // Constructing preimage
        let mut preimage = [big_uint_to_fp(&entry.data_as_big_uint())];

        // // Add username to preimage
        // preimage[0] = big_uint_to_fp(&entry.username_as_big_uint());

        // // Add balances to preimage
        // for (i, balance) in preimage.iter_mut().enumerate().skip(1).take(N_CURRENCIES) {
        //     *balance = big_uint_to_fp(&entry.balances()[i - 1]);
        // }

        Ok(preimage)
    }

    /// Generates a MerkleProof for the user with the given index.
    fn generate_proof(
        &self,
        index: usize,
    ) -> Result<MerkleProof, Box<dyn std::error::Error>>
    {
        let nodes = self.nodes();
        let depth = *self.depth();
        let root = self.root();

        if index >= nodes[0].len() {
            return Err(Box::from("Index out of bounds"));
        }
        assert_eq!(nodes[0].len(), 2usize.pow(depth as u32));

        let mut sibling_middle_node_hash_preimages = Vec::with_capacity(depth - 1);

        let sibling_leaf_index = if index % 2 == 0 { index + 1 } else { index - 1 };

        let sibling_leaf_node_hash_preimage: [Fp; 1] =
            self.get_leaf_node_hash_preimage(sibling_leaf_index)?;
        let mut path_indices = vec![Fp::zero(); depth];
        let mut current_index = index;

        for level in 0..depth {
            let position = current_index % 2;
            let sibling_index = current_index - position + (1 - position);

            // we asserted that the leaves vec length is a power of 2
            // so the index shouldn't overflow the level's length
            if level > 0 {
                // Fetch hash preimage for sibling middle nodes
                let sibling_node_preimage =
                    self.get_middle_node_hash_preimage(level, sibling_index)?;
                sibling_middle_node_hash_preimages.push(sibling_node_preimage);
            }

            path_indices[level] = Fp::from(position as u64);
            current_index /= 2;
        }

        let entry = self.get_entry(index).clone();

        Ok(MerkleProof {
            entry,
            root: root.clone(),
            sibling_leaf_node_hash_preimage,
            sibling_middle_node_hash_preimages,
            path_indices,
        })
    }

    /// Verifies a MerkleProof.
    fn verify_proof(&self, proof: &MerkleProof) -> bool
    {
        let mut node = proof.entry.compute_leaf();

        let sibling_leaf_node =
            Node::leaf_node_from_preimage(&proof.sibling_leaf_node_hash_preimage);

        let mut hash_preimage = [Fp::zero(); 2];
   
        if proof.path_indices[0] == 0.into() {
            hash_preimage[0] = node.hash;
            hash_preimage[1] = sibling_leaf_node.hash;
        } else {
            hash_preimage[0] = sibling_leaf_node.hash;
            hash_preimage[1] = node.hash;
        }
        node = Node::middle_node_from_preimage(&hash_preimage);

        for (i, path_index) in proof.path_indices.iter().enumerate().skip(1) {
            let sibling_node = Node::middle_node_from_preimage(
                &proof.sibling_middle_node_hash_preimages[i - 1],
            );

            let mut hash_preimage = [Fp::zero(); 2];

            if *path_index == 0.into() {
                hash_preimage[0] = node.hash;
                hash_preimage[1] = sibling_node.hash;
            } else {
                hash_preimage[0] = sibling_node.hash;
                hash_preimage[1] = node.hash;
            }
            node = Node::middle_node_from_preimage(&hash_preimage);
        }

        proof.root.hash == node.hash
    }
}
