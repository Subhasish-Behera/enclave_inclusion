# Enclave Inclusion

A Rust/Halo2 prototype for proving inclusion of data entries in a Poseidon-based Merkle tree.

The prototype builds Merkle trees from arbitrary string entries, hashes entry data with Keccak, commits leaves and internal nodes with Poseidon over BN256 scalar fields, and exposes utilities for generating and verifying Merkle inclusion proofs. It also contains reusable Halo2 circuit components for Poseidon hashing and byte-range checks.

## Features

- Poseidon-based Merkle tree construction
- Keccak-backed entry hashing before field conversion
- Inclusion proof generation and verification
- CSV-backed tree construction
- [Optional] sorted tree construction for faster entry lookup
- Halo2 Poseidon chip wrapper
- Halo2 byte range-check chip
- Basic circuit helper traits for witness assignment and public instance exposure

## Project Status

This is an experimental cryptographic prototype. The library code is the main surface area right now; the binary entry point is only a placeholder.

## Requirements

- Rust 1.70+
- Cargo

## Installation

```bash
git clone https://github.com/Subhasish-Behera/enclave_inclusion.git
cd enclave_inclusion
cargo build
```

## Running Tests

```bash
cargo test
```

## Basic Usage

```rust
use gnosis_inclusion::merkle_tree::{Entry, MerkleTree, Tree};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let entries = vec![
        Entry::new("alice".to_string()),
        Entry::new("bob".to_string()),
        Entry::new("charlie".to_string()),
    ];

    let tree = MerkleTree::<32>::from_entries(entries, false)?;

    let proof = tree.generate_proof(0)?;
    assert!(tree.verify_proof(&proof));

    Ok(())
}
```

## CSV Input

A tree can also be built from a CSV file. The current parser reads the first column of each row as the entry data.

```csv
data
alice
bob
charlie
```

```rust
use gnosis_inclusion::merkle_tree::MerkleTree;

let tree = MerkleTree::<32>::from_csv("entries.csv")?;
```

For deterministic lookup ordering, use:

```rust
let tree = MerkleTree::<32>::from_csv_sorted("entries.csv")?;
```

## Crate Layout

```text
src/
  chips/
    poseidon/      # Halo2 Poseidon chip wrapper and Poseidon parameters
    range/         # Halo2 byte range-check chip
  circuits/        # Shared circuit traits and helpers
  merkle_tree/     # Entry, node, tree, CSV parsing, and proof utilities
```

## Core Components

- `Entry`: stores raw string data and its Keccak hash.
- `Node`: represents a Poseidon-committed Merkle node.
- `MerkleTree`: builds trees from entries or CSV files.
- `MerkleProof`: contains sibling preimages and path indices for inclusion verification.
- `RangeCheckChip`: constrains values to fit within a fixed byte width.
- `PoseidonChip`: wraps Halo2's Poseidon gadget for easier reuse in circuits.
