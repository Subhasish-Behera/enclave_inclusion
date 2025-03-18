/// Poseidon Bn254 with WIDTH = 5 and EXPONENTIATION = 5
pub mod poseidon_bn254_5x5;

use std::fmt::Debug;


use halo2_proofs::{circuit::Value, plonk::Expression};
use halo2_proofs::halo2curves::bn256::Fr as Fp;

pub trait Hasher<const WIDTH: usize> {
	/// Creates a new hasher
	fn new(inputs: [Fp; WIDTH]) -> Self;

	/// Finalize the hasher
	fn finalize(&self) -> [Fp; WIDTH];
}
/// Trait definition of Round parameters of Poseidon
pub trait RoundParams<const WIDTH: usize>: Sbox + Clone + Debug {
	/// Returns a number of full rounds.
	fn full_rounds() -> usize;
	/// Returns a number of partial rounds.
	fn partial_rounds() -> usize;

	/// Returns total count size.
	fn round_constants_count() -> usize {
		let partial_rounds = Self::partial_rounds();
		let full_rounds = Self::full_rounds();
		(partial_rounds + full_rounds) * WIDTH
	}

	/// Returns round constants array to be used in permutation.
	fn round_constants() -> Vec<Fp> {
		let round_constants_raw = Self::round_constants_raw();
		let round_constants: Vec<Fp> = round_constants_raw.iter().map(|x| hex_to_field(x)).collect();
		assert_eq!(round_constants.len(), Self::round_constants_count());
		round_constants
	}

	/// Returns relevant constants for the given round.
	fn load_round_constants(round: usize, round_consts: &[Fp]) -> [Fp; WIDTH] {
		let mut result = [Fp::zero(); WIDTH];
		for i in 0..WIDTH {
			result[i] = round_consts[round * WIDTH + i];
		}
		result
	}

	/// Returns MDS matrix with a size of WIDTH x WIDTH.
	fn mds() -> [[Fp; WIDTH]; WIDTH] {
		let mds_raw = Self::mds_raw();
		mds_raw.map(|row| row.map(|item| hex_to_field(item)))
	}

	/// Returns round constants in its hex string form.
	fn round_constants_raw() -> Vec<&'static str>;
	/// Returns MDS martrix in its hex string form.
	fn mds_raw() -> [[&'static str; WIDTH]; WIDTH];
	/// Add round constants to the state values
	/// for the AddRoundConstants operation.
	fn apply_round_constants(state: &[Fp; WIDTH], round_consts: &[Fp; WIDTH]) -> [Fp; WIDTH] {
		let mut next_state = [Fp::zero(); WIDTH];
		for i in 0..WIDTH {
			let state = state[i];
			let round_const = round_consts[i];
			let sum = state + round_const;
			next_state[i] = sum;
		}
		next_state
	}
	/// Compute MDS matrix for MixLayer operation.
	fn apply_mds(state: &[Fp; WIDTH]) -> [Fp; WIDTH] {
		let mut new_state = [Fp::zero(); WIDTH];
		let mds = Self::mds();
		for i in 0..WIDTH {
			for j in 0..WIDTH {
				let mds_ij = &mds[i][j];
				let m_product = state[j] * mds_ij;
				new_state[i] += m_product;
			}
		}
		new_state
	}

	/// Add round constants to the state values
	/// for the AddRoundConstants operation.
	fn apply_round_constants_val(
		state_cells: &[Value<Fp>; WIDTH], round_const_values: &[Value<Fp>; WIDTH],
	) -> [Value<Fp>; WIDTH] {
		let mut next_state = [Value::unknown(); WIDTH];
		for i in 0..WIDTH {
			let round_const = &round_const_values[i];
			let sum = *round_const + state_cells[i];
			next_state[i] = sum;
		}
		next_state
	}

	/// Compute MDS matrix for MixLayer operation.
	fn apply_mds_val(next_state: &[Value<Fp>; WIDTH]) -> [Value<Fp>; WIDTH] {
		let mut new_state = [Value::known(Fp::zero()); WIDTH];
		let mds = Self::mds();
		for i in 0..WIDTH {
			for j in 0..WIDTH {
				let mds_ij = &Value::known(mds[i][j]);
				let m_product = next_state[j] * mds_ij;
				new_state[i] = new_state[i] + m_product;
			}
		}
		new_state
	}

	/// Add round constants expression to the state values
	/// expression for the AddRoundConstants operation in the circuit.
	fn apply_round_constants_expr(
		curr_state: &[Expression<Fp>; WIDTH], round_constants: &[Expression<Fp>; WIDTH],
	) -> [Expression<Fp>; WIDTH] {
		let mut exprs = [(); WIDTH].map(|_| Expression::Constant(Fp::zero()));
		for i in 0..WIDTH {
			exprs[i] = curr_state[i].clone() + round_constants[i].clone();
		}
		exprs
	}

	/// Compute MDS matrix for MixLayer operation in the circuit.
	fn apply_mds_expr(exprs: &[Expression<Fp>; WIDTH]) -> [Expression<Fp>; WIDTH] {
		let mut new_exprs = [(); WIDTH].map(|_| Expression::Constant(Fp::zero()));
		// Mat mul with MDS
		let mds = Self::mds();
		for i in 0..WIDTH {
			for j in 0..WIDTH {
				new_exprs[i] = new_exprs[i].clone() + (exprs[j].clone() * mds[i][j]);
			}
		}
		new_exprs
	}
}

/// Trait explicitly defining S-box operations for field type `Fp`.
pub trait Sbox {
	/// Returns the S-box exponentiation (circuit expression form).
	fn sbox_expr(exp: Expression<Fp>) -> Expression<Fp>;

	/// Returns the S-box exponentiation for the field element explicitly.
	fn sbox_f(f: Fp) -> Fp;

	/// Returns the inverse S-box exponentiation explicitly.
	fn sbox_inv_f(f: Fp) -> Fp;
}

/// Returns the explicit field element (`Fp`) from a given hex string.
pub fn hex_to_field(s: &str) -> Fp {
	let s = s.strip_prefix("0x").unwrap_or(s);
	let mut bytes = hex::decode(s).expect("Invalid hex params");
	bytes.reverse();

	let mut bytes_wide: [u8; 32] = [0; 32];
	bytes_wide[..bytes.len()].copy_from_slice(&bytes[..]);

	Fp::from_bytes(&bytes_wide).expect("Invalid field representation")
}