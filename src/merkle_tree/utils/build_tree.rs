use crate::merkle_tree::{Entry, Node};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use rayon::prelude::*;

pub fn build_merkle_tree_from_leaves(
    leaves: &[Node],
    depth: usize,
) -> Result<(Node, Vec<Vec<Node>>), Box<dyn std::error::Error>>
{
    let mut tree: Vec<Vec<Node>> = Vec::with_capacity(depth + 1);

    // the size of a leaf layer must be a power of 2
    // if not, the `leaves` Vec should be completed with "zero entries" until a power of 2
    assert_eq!(leaves.len(), 2usize.pow(depth as u32));

    tree.push(leaves.to_vec());

    for level in 1..=depth {
        build_middle_level(level, &mut tree)
    }

    let root = tree[depth][0].clone();
    Ok((root, tree))
}

pub fn build_leaves_from_entries(
    entries: &[Entry],
) -> Vec<Node>
{
    // Precompute the zero leaf (this will only be used if we encounter a zero entry)
    let zero_leaf = Entry::zero_entry().compute_leaf();

    let leaves = entries
        .par_iter()
        .map(|entry| {
            // If the entry is the zero entry then we return the precomputed zero leaf
            // Otherwise, we compute the leaf as usual
            if entry == &Entry::zero_entry() {
                zero_leaf.clone()
            } else {
                entry.compute_leaf()
            }
        })
        .collect::<Vec<_>>();

    leaves
}

fn build_middle_level(
    level: usize,
    tree: &mut Vec<Vec<Node>>,
)
{
    let results: Vec<Node> = (0..tree[level - 1].len())
        .into_par_iter()
        .step_by(2)
        .map(|index| {
             // Combine the hashes of the left and right children to create a parent node
             let hash_preimage = [
                tree[level - 1][index].hash,
                tree[level - 1][index + 1].hash,
            ];
            Node::middle_node_from_preimage(&hash_preimage)
        })
        .collect();

    tree.push(results);
}
