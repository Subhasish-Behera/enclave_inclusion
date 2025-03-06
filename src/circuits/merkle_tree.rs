use crate::chips::merkle_tree::{MerkleTreeChip, MerkleTreeConfig};
use crate::chips::poseidon::hash::{PoseidonChip, PoseidonConfig};
use crate::chips::poseidon::poseidon_spec::PoseidonSpec;
//use crate::chips::range::range_check::{RangeCheckChip, RangeCheckConfig};
use crate::circuits::traits::CircuitBase;
use crate::circuits::WithInstances;
use crate::merkle_tree::utils::big_uint_to_fp;
use crate::merkle_tree::{Entry, MerkleProof, Node};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector,
};


#[derive(Clone)]
pub struct MtInclusionCircuit<const LEVELS: usize> {
    pub entry_hash: Entry,
    pub sibling_leaf_node_hash_preimage: [Fp; 1],
    pub sibling_middle_node_hash_preimages: Vec<[Fp; 2]>,
    pub path_indices: Vec<Fp>,
    pub root_hash: Node,
}

impl<const LEVELS: usize> WithInstances for MtInclusionCircuit<LEVELS> {
    /// Returns the number of public inputs of the circuit
    fn num_instances(&self) -> usize {
        2
    }
    /// Returns the values of the public inputs of the circuit. Namely the leaf hash to be verified inclusion of and the root hash of the merkle tree.
    fn instances(&self) -> Vec<Vec<Fp>> {
        vec![vec![self.entry_hash.compute_leaf().hash, self.root_hash.hash]]
    }
}
impl<const LEVELS: usize> CircuitBase for MtInclusionCircuit<LEVELS> {}

impl<const LEVELS: usize> MtInclusionCircuit<LEVELS> {
    pub fn init_empty() -> Self {
        Self {
            entry_hash: Entry::zero_entry(),
            sibling_leaf_node_hash_preimage: [Fp::zero()],
            sibling_middle_node_hash_preimages: vec![[Fp::zero(); 2]; LEVELS - 1],
            path_indices: vec![Fp::zero(); LEVELS],
            root_hash: Node::init_empty(),
        }
    }

    pub fn init(merkle_proof: MerkleProof) -> Self {
        assert_eq!(merkle_proof.path_indices.len(), LEVELS);
        assert_eq!(
            merkle_proof.sibling_middle_node_hash_preimages.len(),
            LEVELS - 1
        );
        Self {
            entry_hash: merkle_proof.entry,
            sibling_leaf_node_hash_preimage: merkle_proof.sibling_leaf_node_hash_preimage,
            sibling_middle_node_hash_preimages: merkle_proof.sibling_middle_node_hash_preimages,
            path_indices: merkle_proof.path_indices,
            root_hash: merkle_proof.root,
        }
    }
}
#[derive(Debug, Clone)]
pub struct MtInclusionConfig {
    //merkle_config: MerkleTreeConfig,
    poseidon_entry_config: PoseidonConfig<2, 1, 1>, // Config for entry hashing
    poseidon_middle_config: PoseidonConfig<2, 1, 2>, // Config for middle hashing
    instance: Column<Instance>,
    advices: [Column<Advice>; 3], // Columns for current hash, sibling hash, and path bit
    fixed_columns: [Column<Fixed>; 4], //2 + 2 for poseidon config.
    //pub merkle_tree_config: MerkleTreeConfig,
    pub merkle_tree_config: MerkleTreeConfig,
}

impl MtInclusionConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        // the max number of advices columns needed is WIDTH + 1 given requirement of the poseidon config
        let advices: [Column<Advice>; 3] = std::array::from_fn(|_| meta.advice_column());

        // we need 2 * WIDTH fixed columns for poseidon config
        let fixed_columns: [Column<Fixed>; 4] = std::array::from_fn(|_| meta.fixed_column());

        // we also need 1 selectors for the MerkleSumTreeChip
        let selectors = meta.selector();

        // we need 1 complex selector for the lookup check in the range check chip
        //let enable_lookup_selector = meta.complex_selector();

        // enable constant for the fixed_column[2], this is required for the poseidon chip and the range check chip
        meta.enable_constant(fixed_columns[2]);

        let poseidon_entry_config =
            PoseidonChip::<PoseidonSpec, 2, 1,  1 >::configure(
                meta,
                advices[0..2].try_into().unwrap(),
                advices[2],
                fixed_columns[0..2].try_into().unwrap(),//for rc_A
                fixed_columns[2..4].try_into().unwrap(),//for rc_B
            );

        // in fact, the poseidon config requires #WIDTH advice columns for state and 1 for partial_sbox, #WIDTH fixed columns for rc_a and #WIDTH for rc_b
        let poseidon_middle_config =
            PoseidonChip::<PoseidonSpec, 2, 1, 2 >::configure(
                meta,
                advices[0..2].try_into().unwrap(),
                advices[2],
                fixed_columns[0..2].try_into().unwrap(),//for rc_A
                fixed_columns[2..4].try_into().unwrap(),//for rc_B
            );

        // enable permutation for all the advice columns
        for col in &advices {
            meta.enable_equality(*col);
        }

        // the configuration of merkle_sum_tree will always require 3 advices, no matter the number of currencies
        let merkle_tree_config = MerkleTreeChip::configure(
            meta,
            advices[0..3].try_into().unwrap(),
            [selectors].try_into().unwrap(),
        );

        // let range_check_config = RangeCheckChip::<N_BYTES>::configure(
        //     meta,
        //     advices[0],
        //     fixed_columns[4],
        //     enable_lookup_selector,
        // );

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self {
            poseidon_entry_config,
            poseidon_middle_config,
            instance,
            advices,
            fixed_columns,
            merkle_tree_config,
        }
        // pub struct MtInclusionConfig {
        //     merkle_config: MerkleTreeConfig,
        //     poseidon_entry_config: PoseidonConfig<2, 1, 1>, // Config for entry hashing
        //     poseidon_middle_config: PoseidonConfig<2, 1, 2>, // Config for middle hashing
        //     instance: Column<Instance>,
        //     advices: [Column<Advice>; 3], // Columns for current hash, sibling hash, and path bit
        //     selector: Selector,
        //     fixed_columns: [Column<Fixed>; 4],
        //     //pub merkle_tree_config: MerkleTreeConfig,
        // }
    }
}


impl<const LEVELS: usize> Circuit<Fp> for MtInclusionCircuit<LEVELS> {
    type Config = MtInclusionConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::init_empty()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        MtInclusionConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        //println!("Levels: {}", LEVELS);
        let merkle_tree_chip = MerkleTreeChip::construct(config.merkle_tree_config);
        let poseidon_leaf = PoseidonChip::<PoseidonSpec, 2, 1, 1>::construct(config.poseidon_entry_config);
        let poseidon_internal = PoseidonChip::<PoseidonSpec, 2, 1, 2>::construct(config.poseidon_middle_config);
        // Assign the entry hash to the witness
        let entry_hash = self.assign_value_to_witness(
            layouter.namespace(|| "assign entry hash"),
            big_uint_to_fp(&self.entry_hash.data_as_big_uint()),
            "entry hash",
            config.advices[0],
        )?;
        //println!("Entry hash assigned: {:?}", entry_hash.value());
        let entry_hasher_input: [AssignedCell<Fp, Fp>; 1] = [entry_hash];

        let mut current_hash = poseidon_leaf.hash(
            layouter.namespace(|| "perform poseidon entry hash"),
            entry_hasher_input,
        )?;

        // Process entry hash
        // let mut current_hash = layouter.assign_region(
        //     || "assign entry hash",
        //     |mut region| {
        //         region.assign_advice(|| "entry hash", config.advices[0], 0, || Ok(self.entry_hash))
        //     },
        // )?;

        self.expose_public(
            layouter.namespace(|| "public leaf hash"),
            &current_hash,
            0,
            config.instance,
         )?;
        for level in 0..LEVELS {
            println!("levels: {}", level);
            let namespace_prefix = format!("level {}", level);
            let sibling_hash: AssignedCell<Fp, Fp>;
            // // Assign the sibling hash to witness
            // let sibling_hash = self.assign_value_to_witness(
            //     layouter.namespace(|| format!("{}: assign sibling hash", namespace_prefix)),
            //     self.sibling_middle_node_hash_preimages[level][0], // First element in pair
            //     "sibling hash",
            //     config.advices[1],
            // )?;
            if level == 0 {
                let sibling_leaf_node_data = self.assign_value_to_witness(
                    layouter.namespace(|| format!("sibling leaf node data")),
                    self.sibling_leaf_node_hash_preimage[0],
                    "sibling leaf node data",
                    config.advices[0],
                )?;

               let  computed_sibling_hash = poseidon_leaf.hash(
                    layouter.namespace(|| format!("{}: perform Poseidon Entry hash", namespace_prefix)),
                    [sibling_leaf_node_data.clone()].try_into().unwrap(), // Convert Vec to Array
                )?;
                //println!("Sibling hash assigned at level {}: {:?}", level, computed_sibling_hash.value());
                sibling_hash = computed_sibling_hash
            }

            else {
                // Assign middle_node_sibling_child_left_hash from middle node hash preimage to the circuit
                let middle_node_sibling_child_left_hash = self.assign_value_to_witness(
                    layouter.namespace(|| format!("sibling left hash")),
                    self.sibling_middle_node_hash_preimages[level - 1][0],
                    "sibling left hash",
                    config.advices[2],
                )?;

                // Assign middle_node_sibling_child_right_hash from middle node hash preimage to the circuit
                let middle_node_sibling_child_right_hash = self.assign_value_to_witness(
                    layouter.namespace(|| format!("sibling right hash")),
                    self.sibling_middle_node_hash_preimages[level - 1][1],
                    "sibling right hash",
                    config.advices[2],
                )?;
                // create an hash_input array of length 2 + N_CURRENCIES that contains the sibling balances, the middle_node_sibling_child_left_hash and the middle_node_sibling_child_right_hash
                let sibling_hasher_input_vec: Vec<AssignedCell<Fp, Fp>> = [middle_node_sibling_child_left_hash].iter()
                    .chain([middle_node_sibling_child_right_hash].iter())
                    .map(|x| x.to_owned())
                    .collect();

                let sibling_hasher_input: [AssignedCell<Fp, Fp>; 2] =
                    match sibling_hasher_input_vec.try_into() {
                        Ok(arr) => arr,
                        Err(_) => panic!("Failed to convert Vec to Array"),
                    };

                // compute the sibling hash
                let computed_sibling_hash = poseidon_internal.hash(
                    layouter.namespace(|| format!("{}: perform poseidon hash", namespace_prefix)),
                    sibling_hasher_input,
                )?;
                //println!("Sibling hash assigned at level {}: {:?}", level, computed_sibling_hash.value());
                sibling_hash = computed_sibling_hash;
            }
            // Assign the swap bit (path index)
            let swap_bit_level = self.assign_value_to_witness(
                layouter.namespace(|| format!("{}: assign swap bit", namespace_prefix)),
                self.path_indices[level],
                "swap bit",
                config.advices[0],
            )?;
            //For every level, perform the swap of the hashes (between `current_hash` and `sibling_hash`) according to the swap bit
            let (hash_left_current, hash_right_current) = merkle_tree_chip
                .swap_hashes_per_level(
                    layouter.namespace(|| format!("{}: swap hashes", namespace_prefix)),
                    &current_hash,
                    &sibling_hash,
                    &swap_bit_level,
                )?;
          //  Swap hashes based on the path index
            let (left_hash_current, right_hash_current) = merkle_tree_chip.swap_hashes_per_level(
                layouter.namespace(|| format!("{}: swap hashes", namespace_prefix)),
                &current_hash,
                &sibling_hash,
                &swap_bit_level,
            )?;
           // println!("Swap bit assigned at level {}: {:?}", level, swap_bit_level.value());

            // Create input for the Poseidon hash (left hash, right hash)
            let middle_hasher_input_vec: Vec<AssignedCell<Fp, Fp>> =
                [left_hash_current, right_hash_current].iter().map(|x| x.to_owned()).collect();

            let middle_hasher_input: [AssignedCell<Fp, Fp>; 2] = match middle_hasher_input_vec.try_into() {
                Ok(arr) => arr,
                Err(_) => panic!("Failed to convert Vec to Array"),
            };

            // Compute the next hash
            let computed_hash = poseidon_internal.hash(
                layouter.namespace(|| format!("{}: perform Poseidon hash", namespace_prefix)),
                middle_hasher_input,
            )?;

            current_hash = computed_hash;
        }



        // Expose root hash as public input
        self.expose_public(layouter.namespace(|| "public root hash"), &current_hash, 1, config.instance)?;
        Ok(())
    }
}
