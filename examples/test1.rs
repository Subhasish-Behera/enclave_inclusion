use halo2_proofs::halo2curves::bn256::Fr as Fp;
//use ff::PrimeField;
use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, Spec},
    Hash as PoseidonHash,
};
use hex;
use halo2_proofs::halo2curves::ff::PrimeField;
// Your existing Node struct
use summa_solvency::merkle_tree::{MerkleTree, Tree,node::Node};
use num_bigint::BigUint;
// Convert from decimal string to Fp
fn decimal_to_fp(value: &str) -> Fp {
    let value_u64 = value.parse::<u64>().expect("Invalid decimal string");
    Fp::from(value_u64)
}
// Convert from Fp to decimal string (for comparing with Solidity uint256 output)
fn fp_to_decimal(value: Fp) -> String {
    // Get bytes in little-endian
    let bytes = value.to_repr();

    // Convert to BigUint (which can represent the full 256-bit value)
    let mut big_uint = BigUint::from(0u32);
    for (i, byte) in bytes.iter().enumerate() {
        big_uint += BigUint::from(*byte) << (i * 8);
    }

    // Convert to decimal string
    big_uint.to_string()
}

// Convert from Fp to Solidity uint256 hex string
fn fp_to_solidity_uint(value: Fp) -> String {
    let mut bytes = value.to_repr();
    bytes.reverse();
    format!("0x{}", hex::encode(bytes))
}
fn fr_to_u256(fr: Fp) -> BigUint {
    // Convert `Fr` to canonical representation (removes Montgomery form)
    let repr = fr.to_repr();

    // Interpret as a big integer in big-endian format (Solidity format)
    BigUint::from_bytes_be(&repr)
}
// Your existing function
// pub fn middle_node_from_preimage(preimage: &[Fp; 2]) -> Node {
//     let hash = PoseidonHash::<Fp, PoseidonSpec, ConstantLength<2>, 3, 2>::init()
//         .hash(preimage.clone());
//     Node { hash }
// }

fn main() {
    // Test values matching your Solidity example
    let input1 = "1";
    let input2 = "2";

    // Convert to Fp
    let fp_input1 = decimal_to_fp(input1);
    let fp_input2 = decimal_to_fp(input2);

    println!("input field elements (hex representation):");
    println!("input1 as Fr: 0x{}", hex::encode(fp_input1.to_repr()));
    println!("input2 as Fr: 0x{}", hex::encode(fp_input2.to_repr()));
    // Create preimage array
    let preimage = [fp_input1, fp_input2];

    // Calculate hash using your existing function
    let node = Node::middle_node_from_preimage(&preimage);
    println!("raw hash result (hex): 0x{}", hex::encode(node.hash.to_repr()));

    // Convert result to Solidity format
    let result_hex = fp_to_decimal(node.hash);

    // Expected result from Solidity
    // You need to run your Solidity function and get the actual result
    //let expected_result = ""; //  output from solidity

    println!("inputs: {} and {}", input1, input2);
    println!("halo2 result: {}", result_hex);
    // println!("Solidity Expected: {}", expected_result);
    // println!("Match: {}", result_hex == expected_result);
    println!("\ntest case 2:");
    let constant1 = Fp::from(1u64);
    let constant3 = Fp::from_str_vartime("1").unwrap();
    println!("constant1: {:?}", constant1);
    let constant2 = Fp::from(2u64);
    let constafnt4 = Fp::from_str_vartime("2").unwrap();
    println!("constant2: {:?}", constant2);

    // Use Poseidon hash function via middle_node_from_preimage
    let preimage = [constant1, constant2];
    let result = Node::middle_node_from_preimage(&preimage);
    println!("result: {:?}", result.hash);
    let uint256_value = fr_to_u256(result.hash);
    println!("node3: {:?}", uint256_value);
}






