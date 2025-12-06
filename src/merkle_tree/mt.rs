use crate::merkle_tree::utils::{
    build_leaves_from_entries, build_merkle_tree_from_leaves, parse_csv_to_entries,
};
use crate::merkle_tree::{Entry, Node, Tree};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use num_bigint::BigUint;

/// Merkle Sum Tree Data Structure.
///
/// A Merkle Sum Tree is a binary Merkle Tree with the following properties:
/// * Each Entry of a Merkle Sum Tree is a pair of a username and #N_CURRENCIES balances.
/// * Each Leaf Node contains a hash and #N_CURRENCIES balances. The hash is equal to `H(username, balance[0], balance[1], ... balance[N_CURRENCIES - 1])`. The balances are equal to the balances associated to the entry
/// * Each Middle Node contains a hash and #N_CURRENCIES balances. The hash is equal to `H(LeftChild.balance[0] + RightChild.balance[0], LeftChild.balance[1] + RightChild.balance[1], ..., LeftChild.balance[N_CURRENCIES - 1] + RightChild.balance[N_CURRENCIES - 1], LeftChild.hash, RightChild.hash)`. The balances are equal to the sum of the balances of the child nodes per each cryptocurrency.
/// * The Root Node represents the committed state of the Tree and contains the sum of all the entries' balances per each cryptocurrency.
///
/// # Type Parameters
///
/// * `N_CURRENCIES`: The number of cryptocurrencies for each user account
/// * `N_BYTES`: Range in which each node balance should lie
#[derive(Debug, Clone)]
pub struct MerkleTree<const N_BYTES: usize> {
    root: Node,
    nodes: Vec<Vec<Node>>,
    depth: usize,
    entries: Vec<Entry>,
    is_sorted: bool,
}

impl<const N_BYTES: usize> Tree
    for MerkleTree<N_BYTES>
{
    fn root(&self) -> &Node {
        &self.root
    }

    fn depth(&self) -> &usize {
        &self.depth
    }

    fn nodes(&self) -> &[Vec<Node>] {
        &self.nodes
    }

    fn get_entry(&self, index: usize) -> &Entry {
        &self.entries[index]
    }
}

impl<const N_BYTES: usize> MerkleTree<N_BYTES> {
    /// Returns the leaves of the tree
    pub fn leaves(&self) -> &[Node] {
        &self.nodes[0]
    }
    /// Returns the entries of the tree
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    /// Builds a Merkle Sum Tree from a CSV file stored at `path`. The CSV file must be formatted as follows:
    ///
    /// `username,balance_<cryptocurrency>_<chain>,balance_<cryptocurrency>_<chain>,...`
    ///
    /// `dxGaEAii,11888,41163`
    pub fn from_csv(path: &str) -> Result<Self, Box<dyn std::error::Error>>
    {
        let entries = parse_csv_to_entries(path)?;
        Self::from_entries(entries, false)
    }

    /// Builds a Merkle Sum Tree from a CSV file stored at `path`. The MST leaves are sorted by the username byte values. The CSV file must be formatted as follows:
    ///
    /// `username,balance_<cryptocurrency>_<chain>,balance_<cryptocurrency>_<chain>,...`
    ///
    /// `dxGaEAii,11888,41163`
    pub fn from_csv_sorted(path: &str) -> Result<Self, Box<dyn std::error::Error>>
    {
        let mut entries = parse_csv_to_entries(path)?;

        entries.sort_by(|a, b| a.data().cmp(b.data()));

        Self::from_entries(entries, true)
    }

    /// Builds a Merkle Sum Tree from a vector of entries
    pub fn from_entries(
        mut entries: Vec<Entry>,
        is_sorted: bool,
    ) -> Result<MerkleTree<N_BYTES>, Box<dyn std::error::Error>>
    {
        let depth = (entries.len() as f64).log2().ceil() as usize;

        // Pad the entries with empty entries to make the number of entries equal to 2^depth
        if entries.len() < 2usize.pow(depth as u32) {
            entries.extend(vec![
                Entry::zero_entry();
                2usize.pow(depth as u32) - entries.len()
            ]);
        }

        let leaves = build_leaves_from_entries(&entries);

        let (root, nodes) = build_merkle_tree_from_leaves(&leaves, depth)?;

        Ok(MerkleTree {
            root,
            nodes,
            depth,
            entries,
            is_sorted,
        })
    }

    /// Builds a Merkle Sum Tree from a root node, a vector of nodes, a depth, a vector of entries, a vector of cryptocurrencies and a boolean indicating whether the leaves are sorted by the username byte values.
    pub fn from_params(
        root: Node,
        nodes: Vec<Vec<Node>>,
        depth: usize,
        entries: Vec<Entry>,
        is_sorted: bool,
    ) -> Result<Self, Box<dyn std::error::Error>>
    {
        Ok(MerkleTree::<N_BYTES> {
            root,
            nodes,
            depth,
            entries,
            is_sorted,
        })
    }


    /// Returns the index of the leaf with the matching username
    pub fn index_of_data(&self, data: &str) -> Result<usize, Box<dyn std::error::Error>> {
        if !self.is_sorted {
            self.entries
                .iter()
                .enumerate()
                .find(|(_, entry)| entry.data() == data)
                .map(|(index, _)| index)
                .ok_or_else(|| Box::from("Data not found"))
        } else {
            self.entries
                .binary_search_by_key(&data, |entry| entry.data())
                .map_err(|_| Box::from("Data not found"))
        }
    }
}
