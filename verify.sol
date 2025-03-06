// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Verifier {
    uint256 internal constant    PROOF_LEN_CPTR = 0x44;
    uint256 internal constant        PROOF_CPTR = 0x64;
    uint256 internal constant NUM_INSTANCE_CPTR = 0x0724;
    uint256 internal constant     INSTANCE_CPTR = 0x0744;

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x01e4;
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = 0x02e4;

    uint256 internal constant                VK_MPTR = 0x05e0;
    uint256 internal constant         VK_DIGEST_MPTR = 0x05e0;
    uint256 internal constant                 K_MPTR = 0x0600;
    uint256 internal constant             N_INV_MPTR = 0x0620;
    uint256 internal constant             OMEGA_MPTR = 0x0640;
    uint256 internal constant         OMEGA_INV_MPTR = 0x0660;
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = 0x0680;
    uint256 internal constant     NUM_INSTANCES_MPTR = 0x06a0;
    uint256 internal constant   HAS_ACCUMULATOR_MPTR = 0x06c0;
    uint256 internal constant        ACC_OFFSET_MPTR = 0x06e0;
    uint256 internal constant     NUM_ACC_LIMBS_MPTR = 0x0700;
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = 0x0720;
    uint256 internal constant              G1_X_MPTR = 0x0740;
    uint256 internal constant              G1_Y_MPTR = 0x0760;
    uint256 internal constant            G2_X_1_MPTR = 0x0780;
    uint256 internal constant            G2_X_2_MPTR = 0x07a0;
    uint256 internal constant            G2_Y_1_MPTR = 0x07c0;
    uint256 internal constant            G2_Y_2_MPTR = 0x07e0;
    uint256 internal constant      NEG_S_G2_X_1_MPTR = 0x0800;
    uint256 internal constant      NEG_S_G2_X_2_MPTR = 0x0820;
    uint256 internal constant      NEG_S_G2_Y_1_MPTR = 0x0840;
    uint256 internal constant      NEG_S_G2_Y_2_MPTR = 0x0860;

    uint256 internal constant CHALLENGE_MPTR = 0x0c40;

    uint256 internal constant THETA_MPTR = 0x0c40;
    uint256 internal constant  BETA_MPTR = 0x0c60;
    uint256 internal constant GAMMA_MPTR = 0x0c80;
    uint256 internal constant     Y_MPTR = 0x0ca0;
    uint256 internal constant     X_MPTR = 0x0cc0;
    uint256 internal constant  ZETA_MPTR = 0x0ce0;
    uint256 internal constant    NU_MPTR = 0x0d00;
    uint256 internal constant    MU_MPTR = 0x0d20;

    uint256 internal constant       ACC_LHS_X_MPTR = 0x0d40;
    uint256 internal constant       ACC_LHS_Y_MPTR = 0x0d60;
    uint256 internal constant       ACC_RHS_X_MPTR = 0x0d80;
    uint256 internal constant       ACC_RHS_Y_MPTR = 0x0da0;
    uint256 internal constant             X_N_MPTR = 0x0dc0;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x0de0;
    uint256 internal constant          L_LAST_MPTR = 0x0e00;
    uint256 internal constant         L_BLIND_MPTR = 0x0e20;
    uint256 internal constant             L_0_MPTR = 0x0e40;
    uint256 internal constant   INSTANCE_EVAL_MPTR = 0x0e60;
    uint256 internal constant   QUOTIENT_EVAL_MPTR = 0x0e80;
    uint256 internal constant      QUOTIENT_X_MPTR = 0x0ea0;
    uint256 internal constant      QUOTIENT_Y_MPTR = 0x0ec0;
    uint256 internal constant          R_EVAL_MPTR = 0x0ee0;
    uint256 internal constant   PAIRING_LHS_X_MPTR = 0x0f00;
    uint256 internal constant   PAIRING_LHS_Y_MPTR = 0x0f20;
    uint256 internal constant   PAIRING_RHS_X_MPTR = 0x0f40;
    uint256 internal constant   PAIRING_RHS_Y_MPTR = 0x0f60;

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) public returns (bool) {
        assembly {
            // Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20),
            // and check if the point is on affine plane,
            // and store them in (hash_mptr, hash_mptr + 0x20).
            // Return updated (success, proof_cptr, hash_mptr).
            function read_ec_point(success, proof_cptr, hash_mptr, q) -> ret0, ret1, ret2 {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret0 := and(success, lt(x, q))
                ret0 := and(ret0, lt(y, q))
                ret0 := and(ret0, eq(mulmod(y, y, q), addmod(mulmod(x, mulmod(x, x, q), q), 3, q)))
                mstore(hash_mptr, x)
                mstore(add(hash_mptr, 0x20), y)
                ret1 := add(proof_cptr, 0x40)
                ret2 := add(hash_mptr, 0x40)
            }

            // Squeeze challenge by keccak256(memory[0..hash_mptr]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr, hash_mptr).
            function squeeze_challenge(challenge_mptr, hash_mptr, r) -> ret0, ret1 {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze challenge without absorbing new input from calldata,
            // by putting an extra 0x01 in memory[0x20] and squeeze by keccak256(memory[0..21]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr).
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Batch invert values in memory[mptr_start..mptr_end] in place.
            // Return updated (success).
            function batch_invert(success, mptr_start, mptr_end, r) -> ret {
                let gp_mptr := mptr_end
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for
                    {}
                    lt(mptr, sub(mptr_end, 0x20))
                    {}
                {
                    gp := mulmod(gp, mload(mptr), r)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), r)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(r, 2))
                mstore(add(gp_mptr, 0xa0), r)
                ret := and(success, staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20))
                let all_inv := mload(gp_mptr)

                let first_mptr := mptr_start
                let second_mptr := add(first_mptr, 0x20)
                gp_mptr := sub(gp_mptr, 0x20)
                for
                    {}
                    lt(second_mptr, mptr)
                    {}
                {
                    let inv := mulmod(all_inv, mload(gp_mptr), r)
                    all_inv := mulmod(all_inv, mload(mptr), r)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(second_mptr), r)
                let inv_second := mulmod(all_inv, mload(first_mptr), r)
                mstore(first_mptr, inv_first)
                mstore(second_mptr, inv_second)
            }

            // Add (x, y) into point at (0x00, 0x20).
            // Return updated (success).
            function ec_add_acc(success, x, y) -> ret {
                mstore(0x40, x)
                mstore(0x60, y)
                ret := and(success, staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40))
            }

            // Scale point at (0x00, 0x20) by scalar.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x40, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x00, 0x60, 0x00, 0x40))
            }

            // Add (x, y) into point at (0x80, 0xa0).
            // Return updated (success).
            function ec_add_tmp(success, x, y) -> ret {
                mstore(0xc0, x)
                mstore(0xe0, y)
                ret := and(success, staticcall(gas(), 0x06, 0x80, 0x80, 0x80, 0x40))
            }

            // Scale point at (0x80, 0xa0) by scalar.
            // Return updated (success).
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0xc0, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x80, 0x60, 0x80, 0x40))
            }

            // Perform pairing check.
            // Return updated (success).
            function ec_pairing(success, lhs_x, lhs_y, rhs_x, rhs_y) -> ret {
                mstore(0x00, lhs_x)
                mstore(0x20, lhs_y)
                mstore(0x40, mload(G2_X_1_MPTR))
                mstore(0x60, mload(G2_X_2_MPTR))
                mstore(0x80, mload(G2_Y_1_MPTR))
                mstore(0xa0, mload(G2_Y_2_MPTR))
                mstore(0xc0, rhs_x)
                mstore(0xe0, rhs_y)
                mstore(0x100, mload(NEG_S_G2_X_1_MPTR))
                mstore(0x120, mload(NEG_S_G2_X_2_MPTR))
                mstore(0x140, mload(NEG_S_G2_Y_1_MPTR))
                mstore(0x160, mload(NEG_S_G2_Y_2_MPTR))
                ret := and(success, staticcall(gas(), 0x08, 0x00, 0x180, 0x00, 0x20))
                ret := and(ret, mload(0x00))
            }

            // Modulus
            let q := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // BN254 base field
            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // BN254 scalar field

            // Initialize success as true
            let success := true

            {
                // Load vk into memory
                mstore(0x05e0, 0x13d071a7fb9e612f73319bf9104331c724f4f0f4ced3b63bca9c6142078f7696) // vk_digest
                mstore(0x0600, 0x000000000000000000000000000000000000000000000000000000000000000b) // k
                mstore(0x0620, 0x305e41e912d579f5b3193badcab128321c8ee1cb70aa396331b979553d820001) // n_inv
                mstore(0x0640, 0x14c60185e75885d674db4b3f7d4a5694fa6c01aa0f53557b060bc04a4172705f) // omega
                mstore(0x0660, 0x2afd4e77273f1cb3434a4a667929058c156b21573c3f1efc882e708597d7161a) // omega_inv
                mstore(0x0680, 0x22b55603586d5fc42c6c14c2fc27a028c207da8b2c71cb33d549fa4a2be5d302) // omega_inv_to_l
                mstore(0x06a0, 0x0000000000000000000000000000000000000000000000000000000000000002) // num_instances
                mstore(0x06c0, 0x0000000000000000000000000000000000000000000000000000000000000000) // has_accumulator
                mstore(0x06e0, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
                mstore(0x0700, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limbs
                mstore(0x0720, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limb_bits
                mstore(0x0740, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
                mstore(0x0760, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
                mstore(0x0780, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
                mstore(0x07a0, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
                mstore(0x07c0, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
                mstore(0x07e0, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
                mstore(0x0800, 0x26186a2d65ee4d2f9c9a5b91f86597d35f192cd120caf7e935d8443d1938e23d) // neg_s_g2_x_1
                mstore(0x0820, 0x30441fd1b5d3370482c42152a8899027716989a6996c2535bc9f7fee8aaef79e) // neg_s_g2_x_2
                mstore(0x0840, 0x16f363f103c80d7bbc8ad3c6867e0822bbc6000be91a4689755c7df40221c145) // neg_s_g2_y_1
                mstore(0x0860, 0x2b1cbb3e521edf5a622d82762a44a5e63f1e50b332d71154a4a7958d6011deff) // neg_s_g2_y_2
                mstore(0x0880, 0x2ce01250d4ea6096e6eebe7b774ec4f2a45a5011d798786c6b2ab6448e8aa447) // fixed_comms[0].x
                mstore(0x08a0, 0x16047770775b41ddf2f0c3049c7bfa5342618a9a98ebbbf118131a7576a92560) // fixed_comms[0].y
                mstore(0x08c0, 0x285233dcaf0f77ced0d7eb5b963e36943766b910e2b708bfdb357bfc95db1cd7) // fixed_comms[1].x
                mstore(0x08e0, 0x00a5f2a96b8510d3f418ae0857d59126100951870be21417c71a5aecb75f5dc3) // fixed_comms[1].y
                mstore(0x0900, 0x2dd39e5cad23413cebee9c1c2783be5808c261d4678b08e08aa152e9332e7dc9) // fixed_comms[2].x
                mstore(0x0920, 0x1325aed07dd8181ee9b08ae996008687132e4a011c4ac8e821090f33c391ac75) // fixed_comms[2].y
                mstore(0x0940, 0x20171145c538141d64489ca61af219778fcf627dce990a290b130f2de6acfc81) // fixed_comms[3].x
                mstore(0x0960, 0x2f61105c10fbb1fa1d8e96f964968955640adaa4b95e98580799eef165a4c63c) // fixed_comms[3].y
                mstore(0x0980, 0x15fc25a1c47f5fdfa6cb8870ec3b473bc5a0736b2544a86b158ef5eb0aba5118) // fixed_comms[4].x
                mstore(0x09a0, 0x2cfdd6bc481ef3ee7722042a0e8e708cce5243b6ec02538ad8da9d7d32a386c8) // fixed_comms[4].y
                mstore(0x09c0, 0x1658aecc65e05be7f96a5a166326efa0307f0b0b0b0ef41b950fa63a65f44c71) // fixed_comms[5].x
                mstore(0x09e0, 0x08969bc1b6e0140d8b98f32c982dc079b674924b6213714d61db9820b92a21c6) // fixed_comms[5].y
                mstore(0x0a00, 0x090228d84c5ee50d2092b6690747d92e9f48fce3b8140d7b37b07a46f07c6382) // fixed_comms[6].x
                mstore(0x0a20, 0x1b16e887500490d3834b34d33044e0bc1dfe35ee6de70bd5bb0cafff8e494436) // fixed_comms[6].y
                mstore(0x0a40, 0x10bd4d69cc8223c60afea50263ed66fa09cb16525162e566230a661232e2f6d5) // fixed_comms[7].x
                mstore(0x0a60, 0x111545a5b089f32f8138688051564a02a35207d5dc292fb7276ca9655173669f) // fixed_comms[7].y
                mstore(0x0a80, 0x2f8c9597ad5764ba414046ed1257ab258582a9d370ec115d78b990dec7c0bc1d) // fixed_comms[8].x
                mstore(0x0aa0, 0x0cea93d2c4476add40f7aa6ef6ef49bd567f43f9a2bb2cc78750aee865805e00) // fixed_comms[8].y
                mstore(0x0ac0, 0x22f3ef7d73648eeccf4239ab77e62be821c2ba2e631f8646470c6a63bb491fa5) // permutation_comms[0].x
                mstore(0x0ae0, 0x286aca1353daac9a6a5532b7427bcee9e424ad3e581eec37fd5f36450c6880d9) // permutation_comms[0].y
                mstore(0x0b00, 0x1a606bbe3f7db59283dbff6509e37d76b25e84ae1f8c51303fe99c56b4b5bc0e) // permutation_comms[1].x
                mstore(0x0b20, 0x255a4f7b88f3bd132cd1df1ceae70c47659c6faf62d273ed16b332bbef2670bb) // permutation_comms[1].y
                mstore(0x0b40, 0x01366c97f8588616aedb01391d60303e30b5931f3d866ca489064e6aea7d9a6a) // permutation_comms[2].x
                mstore(0x0b60, 0x09bdbf04b7fe45610b3a63f60ad679b4130b00a5c5bc2e8d3b649a3aed613782) // permutation_comms[2].y
                mstore(0x0b80, 0x0743ea40f14084db2673217283aa053f986896ee7c181f52118442e99c452974) // permutation_comms[3].x
                mstore(0x0ba0, 0x0203e3493a2594ece57d22cc75dd081ac68271ec7c758153cfd2152bfb5c19e3) // permutation_comms[3].y
                mstore(0x0bc0, 0x2e68f521b8db38020f708e54c4d75e1dad13f7f1db4ab0d62da2affc85dbee4a) // permutation_comms[4].x
                mstore(0x0be0, 0x20075f1b822ad32716646bb58f630e73e340f64d81b601aeccd45549e89ef163) // permutation_comms[4].y
                mstore(0x0c00, 0x25b1262cd5bcffb6c37e2f73d250ee3395979518ffee8becf98e10dd2513040f) // permutation_comms[5].x
                mstore(0x0c20, 0x0220f08ae1b39e7ec18f644e20084aa3d86f36787815d99e32311acebbed59e1) // permutation_comms[5].y

                // Check valid length of proof
                success := and(success, eq(0x06c0, calldataload(PROOF_LEN_CPTR)))

                // Check valid length of instances
                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(success, eq(num_instances, calldataload(NUM_INSTANCE_CPTR)))

                // Absorb vk diegst
                mstore(0x00, mload(VK_DIGEST_MPTR))

                // Read instances and witness commitments and generate challenges
                let hash_mptr := 0x20
                let instance_cptr := INSTANCE_CPTR
                for
                    { let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances)) }
                    lt(instance_cptr, instance_cptr_end)
                    {}
                {
                    let instance := calldataload(instance_cptr)
                    success := and(success, lt(instance, r))
                    mstore(hash_mptr, instance)
                    instance_cptr := add(instance_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                let proof_cptr := PROOF_CPTR
                let challenge_mptr := CHALLENGE_MPTR

                // Phase 1
                for
                    { let proof_cptr_end := add(proof_cptr, 0xc0) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)

                // Phase 2
                for
                    { let proof_cptr_end := add(proof_cptr, 0xc0) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 3
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0140) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Read evaluations
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0380) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    let eval := calldataload(proof_cptr)
                    success := and(success, lt(eval, r))
                    mstore(hash_mptr, eval)
                    proof_cptr := add(proof_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                // Read batch opening proof and generate challenges
                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // zeta
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)                        // nu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // mu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W'

                // Read accumulator from instances
                if mload(HAS_ACCUMULATOR_MPTR) {
                    let num_limbs := mload(NUM_ACC_LIMBS_MPTR)
                    let num_limb_bits := mload(NUM_ACC_LIMB_BITS_MPTR)

                    let cptr := add(INSTANCE_CPTR, mul(mload(ACC_OFFSET_MPTR), 0x20))
                    let lhs_y_off := mul(num_limbs, 0x20)
                    let rhs_x_off := mul(lhs_y_off, 2)
                    let rhs_y_off := mul(lhs_y_off, 3)
                    let lhs_x := calldataload(cptr)
                    let lhs_y := calldataload(add(cptr, lhs_y_off))
                    let rhs_x := calldataload(add(cptr, rhs_x_off))
                    let rhs_y := calldataload(add(cptr, rhs_y_off))
                    for
                        {
                            let cptr_end := add(cptr, mul(0x20, num_limbs))
                            let shift := num_limb_bits
                        }
                        lt(cptr, cptr_end)
                        {}
                    {
                        cptr := add(cptr, 0x20)
                        lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))
                        lhs_y := add(lhs_y, shl(shift, calldataload(add(cptr, lhs_y_off))))
                        rhs_x := add(rhs_x, shl(shift, calldataload(add(cptr, rhs_x_off))))
                        rhs_y := add(rhs_y, shl(shift, calldataload(add(cptr, rhs_y_off))))
                        shift := add(shift, num_limb_bits)
                    }

                    success := and(success, eq(mulmod(lhs_y, lhs_y, q), addmod(mulmod(lhs_x, mulmod(lhs_x, lhs_x, q), q), 3, q)))
                    success := and(success, eq(mulmod(rhs_y, rhs_y, q), addmod(mulmod(rhs_x, mulmod(rhs_x, rhs_x, q), q), 3, q)))

                    mstore(ACC_LHS_X_MPTR, lhs_x)
                    mstore(ACC_LHS_Y_MPTR, lhs_y)
                    mstore(ACC_RHS_X_MPTR, rhs_x)
                    mstore(ACC_RHS_Y_MPTR, rhs_y)
                }

                pop(q)
            }

            // Revert earlier if anything from calldata is invalid
            if iszero(success) {
                revert(0, 0)
            }

            // Compute lagrange evaluations and instance evaluation
            {
                let k := mload(K_MPTR)
                let x := mload(X_MPTR)
                let x_n := x
                for
                    { let idx := 0 }
                    lt(idx, k)
                    { idx := add(idx, 1) }
                {
                    x_n := mulmod(x_n, x_n, r)
                }

                let omega := mload(OMEGA_MPTR)

                let mptr := X_N_MPTR
                let mptr_end := add(mptr, mul(0x20, add(mload(NUM_INSTANCES_MPTR), 6)))
                if iszero(mload(NUM_INSTANCES_MPTR)) {
                    mptr_end := add(mptr_end, 0x20)
                }
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, addmod(x, sub(r, pow_of_omega), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }
                let x_n_minus_1 := addmod(x_n, sub(r, 1), r)
                mstore(mptr_end, x_n_minus_1)
                success := batch_invert(success, X_N_MPTR, add(mptr_end, 0x20), r)

                mptr := X_N_MPTR
                let l_i_common := mulmod(x_n_minus_1, mload(N_INV_MPTR), r)
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, mulmod(l_i_common, mulmod(mload(mptr), pow_of_omega, r), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }

                let l_blind := mload(add(X_N_MPTR, 0x20))
                let l_i_cptr := add(X_N_MPTR, 0x40)
                for
                    { let l_i_cptr_end := add(X_N_MPTR, 0xc0) }
                    lt(l_i_cptr, l_i_cptr_end)
                    { l_i_cptr := add(l_i_cptr, 0x20) }
                {
                    l_blind := addmod(l_blind, mload(l_i_cptr), r)
                }

                let instance_eval := 0
                for
                    {
                        let instance_cptr := INSTANCE_CPTR
                        let instance_cptr_end := add(instance_cptr, mul(0x20, mload(NUM_INSTANCES_MPTR)))
                    }
                    lt(instance_cptr, instance_cptr_end)
                    {
                        instance_cptr := add(instance_cptr, 0x20)
                        l_i_cptr := add(l_i_cptr, 0x20)
                    }
                {
                    instance_eval := addmod(instance_eval, mulmod(mload(l_i_cptr), calldataload(instance_cptr), r), r)
                }

                let x_n_minus_1_inv := mload(mptr_end)
                let l_last := mload(X_N_MPTR)
                let l_0 := mload(add(X_N_MPTR, 0xc0))

                mstore(X_N_MPTR, x_n)
                mstore(X_N_MINUS_1_INV_MPTR, x_n_minus_1_inv)
                mstore(L_LAST_MPTR, l_last)
                mstore(L_BLIND_MPTR, l_blind)
                mstore(L_0_MPTR, l_0)
                mstore(INSTANCE_EVAL_MPTR, instance_eval)
            }

            // Compute quotient evavluation
            {
                let quotient_eval_numer
                let delta := 4131629893567559867359510883348571134090853742863529169391034518566172092834
                let y := mload(Y_MPTR)
                {
                    let f_5 := calldataload(0x04a4)
                    let a_0 := calldataload(0x0324)
                    let f_0 := calldataload(0x0444)
                    let var0 := addmod(a_0, f_0, r)
                    let var1 := mulmod(var0, var0, r)
                    let var2 := mulmod(var1, var1, r)
                    let var3 := mulmod(var2, var0, r)
                    let var4 := mulmod(var3, 0x066f6f85d6f68a85ec10345351a23a3aaf07f38af8c952a7bceca70bd2af7ad5, r)
                    let a_1 := calldataload(0x0344)
                    let f_1 := calldataload(0x0464)
                    let var5 := addmod(a_1, f_1, r)
                    let var6 := mulmod(var5, var5, r)
                    let var7 := mulmod(var6, var6, r)
                    let var8 := mulmod(var7, var5, r)
                    let var9 := mulmod(var8, 0x2b9d4b4110c9ae997782e1509b1d0fdb20a7c02bbd8bea7305462b9f8125b1e8, r)
                    let var10 := addmod(var4, var9, r)
                    let a_0_next_1 := calldataload(0x0364)
                    let var11 := sub(r, a_0_next_1)
                    let var12 := addmod(var10, var11, r)
                    let var13 := mulmod(f_5, var12, r)
                    quotient_eval_numer := var13
                }
                {
                    let f_5 := calldataload(0x04a4)
                    let a_0 := calldataload(0x0324)
                    let f_0 := calldataload(0x0444)
                    let var0 := addmod(a_0, f_0, r)
                    let var1 := mulmod(var0, var0, r)
                    let var2 := mulmod(var1, var1, r)
                    let var3 := mulmod(var2, var0, r)
                    let var4 := mulmod(var3, 0x0cc57cdbb08507d62bf67a4493cc262fb6c09d557013fff1f573f431221f8ff9, r)
                    let a_1 := calldataload(0x0344)
                    let f_1 := calldataload(0x0464)
                    let var5 := addmod(a_1, f_1, r)
                    let var6 := mulmod(var5, var5, r)
                    let var7 := mulmod(var6, var6, r)
                    let var8 := mulmod(var7, var5, r)
                    let var9 := mulmod(var8, 0x1274e649a32ed355a31a6ed69724e1adade857e86eb5c3a121bcd147943203c8, r)
                    let var10 := addmod(var4, var9, r)
                    let a_1_next_1 := calldataload(0x0384)
                    let var11 := sub(r, a_1_next_1)
                    let var12 := addmod(var10, var11, r)
                    let var13 := mulmod(f_5, var12, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_6 := calldataload(0x04c4)
                    let a_0 := calldataload(0x0324)
                    let f_0 := calldataload(0x0444)
                    let var0 := addmod(a_0, f_0, r)
                    let var1 := mulmod(var0, var0, r)
                    let var2 := mulmod(var1, var1, r)
                    let var3 := mulmod(var2, var0, r)
                    let a_2 := calldataload(0x03a4)
                    let var4 := sub(r, a_2)
                    let var5 := addmod(var3, var4, r)
                    let var6 := mulmod(f_6, var5, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var6, r)
                }
                {
                    let f_6 := calldataload(0x04c4)
                    let a_2 := calldataload(0x03a4)
                    let var0 := mulmod(a_2, 0x066f6f85d6f68a85ec10345351a23a3aaf07f38af8c952a7bceca70bd2af7ad5, r)
                    let a_1 := calldataload(0x0344)
                    let f_1 := calldataload(0x0464)
                    let var1 := addmod(a_1, f_1, r)
                    let var2 := mulmod(var1, 0x2b9d4b4110c9ae997782e1509b1d0fdb20a7c02bbd8bea7305462b9f8125b1e8, r)
                    let var3 := addmod(var0, var2, r)
                    let f_2 := calldataload(0x0404)
                    let var4 := addmod(var3, f_2, r)
                    let var5 := mulmod(var4, var4, r)
                    let var6 := mulmod(var5, var5, r)
                    let var7 := mulmod(var6, var4, r)
                    let a_0_next_1 := calldataload(0x0364)
                    let var8 := mulmod(a_0_next_1, 0x13abec390ada7f4370819ab1c7846f210554569d9b29d1ea8dbebd0fa8c53e66, r)
                    let a_1_next_1 := calldataload(0x0384)
                    let var9 := mulmod(a_1_next_1, 0x1eb9e1dc19a33a624c9862a1d97d1510bd521ead5dfe0345aaf6185b1a1e60fe, r)
                    let var10 := addmod(var8, var9, r)
                    let var11 := sub(r, var10)
                    let var12 := addmod(var7, var11, r)
                    let var13 := mulmod(f_6, var12, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_6 := calldataload(0x04c4)
                    let a_2 := calldataload(0x03a4)
                    let var0 := mulmod(a_2, 0x0cc57cdbb08507d62bf67a4493cc262fb6c09d557013fff1f573f431221f8ff9, r)
                    let a_1 := calldataload(0x0344)
                    let f_1 := calldataload(0x0464)
                    let var1 := addmod(a_1, f_1, r)
                    let var2 := mulmod(var1, 0x1274e649a32ed355a31a6ed69724e1adade857e86eb5c3a121bcd147943203c8, r)
                    let var3 := addmod(var0, var2, r)
                    let f_3 := calldataload(0x0424)
                    let var4 := addmod(var3, f_3, r)
                    let a_0_next_1 := calldataload(0x0364)
                    let var5 := mulmod(a_0_next_1, 0x0fc1c9394db89bb2601abc49fdad4f038ce5169030a2ad69763f7875036bcb02, r)
                    let a_1_next_1 := calldataload(0x0384)
                    let var6 := mulmod(a_1_next_1, 0x16a9e98c493a902b9502054edc03e7b22b7eac34345961bc8abced6bd147c8be, r)
                    let var7 := addmod(var5, var6, r)
                    let var8 := sub(r, var7)
                    let var9 := addmod(var4, var8, r)
                    let var10 := mulmod(f_6, var9, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_4 := calldataload(0x0484)
                    let var0 := 0x1
                    let var1 := sub(r, f_4)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_4, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_0_prev_1 := calldataload(0x03e4)
                    let a_0 := calldataload(0x0324)
                    let var7 := addmod(a_0_prev_1, a_0, r)
                    let a_0_next_1 := calldataload(0x0364)
                    let var8 := sub(r, a_0_next_1)
                    let var9 := addmod(var7, var8, r)
                    let var10 := mulmod(var6, var9, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_4 := calldataload(0x0484)
                    let var0 := 0x1
                    let var1 := sub(r, f_4)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_4, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_1_prev_1 := calldataload(0x03c4)
                    let a_1_next_1 := calldataload(0x0384)
                    let var7 := sub(r, a_1_next_1)
                    let var8 := addmod(a_1_prev_1, var7, r)
                    let var9 := mulmod(var6, var8, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var9, r)
                }
                {
                    let f_7 := calldataload(0x04e4)
                    let a_0 := calldataload(0x0324)
                    let f_0 := calldataload(0x0444)
                    let var0 := addmod(a_0, f_0, r)
                    let var1 := mulmod(var0, var0, r)
                    let var2 := mulmod(var1, var1, r)
                    let var3 := mulmod(var2, var0, r)
                    let var4 := mulmod(var3, 0x066f6f85d6f68a85ec10345351a23a3aaf07f38af8c952a7bceca70bd2af7ad5, r)
                    let a_1 := calldataload(0x0344)
                    let f_1 := calldataload(0x0464)
                    let var5 := addmod(a_1, f_1, r)
                    let var6 := mulmod(var5, var5, r)
                    let var7 := mulmod(var6, var6, r)
                    let var8 := mulmod(var7, var5, r)
                    let var9 := mulmod(var8, 0x2b9d4b4110c9ae997782e1509b1d0fdb20a7c02bbd8bea7305462b9f8125b1e8, r)
                    let var10 := addmod(var4, var9, r)
                    let a_0_next_1 := calldataload(0x0364)
                    let var11 := sub(r, a_0_next_1)
                    let var12 := addmod(var10, var11, r)
                    let var13 := mulmod(f_7, var12, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_7 := calldataload(0x04e4)
                    let a_0 := calldataload(0x0324)
                    let f_0 := calldataload(0x0444)
                    let var0 := addmod(a_0, f_0, r)
                    let var1 := mulmod(var0, var0, r)
                    let var2 := mulmod(var1, var1, r)
                    let var3 := mulmod(var2, var0, r)
                    let var4 := mulmod(var3, 0x0cc57cdbb08507d62bf67a4493cc262fb6c09d557013fff1f573f431221f8ff9, r)
                    let a_1 := calldataload(0x0344)
                    let f_1 := calldataload(0x0464)
                    let var5 := addmod(a_1, f_1, r)
                    let var6 := mulmod(var5, var5, r)
                    let var7 := mulmod(var6, var6, r)
                    let var8 := mulmod(var7, var5, r)
                    let var9 := mulmod(var8, 0x1274e649a32ed355a31a6ed69724e1adade857e86eb5c3a121bcd147943203c8, r)
                    let var10 := addmod(var4, var9, r)
                    let a_1_next_1 := calldataload(0x0384)
                    let var11 := sub(r, a_1_next_1)
                    let var12 := addmod(var10, var11, r)
                    let var13 := mulmod(f_7, var12, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_8 := calldataload(0x0504)
                    let a_0 := calldataload(0x0324)
                    let f_0 := calldataload(0x0444)
                    let var0 := addmod(a_0, f_0, r)
                    let var1 := mulmod(var0, var0, r)
                    let var2 := mulmod(var1, var1, r)
                    let var3 := mulmod(var2, var0, r)
                    let a_2 := calldataload(0x03a4)
                    let var4 := sub(r, a_2)
                    let var5 := addmod(var3, var4, r)
                    let var6 := mulmod(f_8, var5, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var6, r)
                }
                {
                    let f_8 := calldataload(0x0504)
                    let a_2 := calldataload(0x03a4)
                    let var0 := mulmod(a_2, 0x066f6f85d6f68a85ec10345351a23a3aaf07f38af8c952a7bceca70bd2af7ad5, r)
                    let a_1 := calldataload(0x0344)
                    let f_1 := calldataload(0x0464)
                    let var1 := addmod(a_1, f_1, r)
                    let var2 := mulmod(var1, 0x2b9d4b4110c9ae997782e1509b1d0fdb20a7c02bbd8bea7305462b9f8125b1e8, r)
                    let var3 := addmod(var0, var2, r)
                    let f_2 := calldataload(0x0404)
                    let var4 := addmod(var3, f_2, r)
                    let var5 := mulmod(var4, var4, r)
                    let var6 := mulmod(var5, var5, r)
                    let var7 := mulmod(var6, var4, r)
                    let a_0_next_1 := calldataload(0x0364)
                    let var8 := mulmod(a_0_next_1, 0x13abec390ada7f4370819ab1c7846f210554569d9b29d1ea8dbebd0fa8c53e66, r)
                    let a_1_next_1 := calldataload(0x0384)
                    let var9 := mulmod(a_1_next_1, 0x1eb9e1dc19a33a624c9862a1d97d1510bd521ead5dfe0345aaf6185b1a1e60fe, r)
                    let var10 := addmod(var8, var9, r)
                    let var11 := sub(r, var10)
                    let var12 := addmod(var7, var11, r)
                    let var13 := mulmod(f_8, var12, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_8 := calldataload(0x0504)
                    let a_2 := calldataload(0x03a4)
                    let var0 := mulmod(a_2, 0x0cc57cdbb08507d62bf67a4493cc262fb6c09d557013fff1f573f431221f8ff9, r)
                    let a_1 := calldataload(0x0344)
                    let f_1 := calldataload(0x0464)
                    let var1 := addmod(a_1, f_1, r)
                    let var2 := mulmod(var1, 0x1274e649a32ed355a31a6ed69724e1adade857e86eb5c3a121bcd147943203c8, r)
                    let var3 := addmod(var0, var2, r)
                    let f_3 := calldataload(0x0424)
                    let var4 := addmod(var3, f_3, r)
                    let a_0_next_1 := calldataload(0x0364)
                    let var5 := mulmod(a_0_next_1, 0x0fc1c9394db89bb2601abc49fdad4f038ce5169030a2ad69763f7875036bcb02, r)
                    let a_1_next_1 := calldataload(0x0384)
                    let var6 := mulmod(a_1_next_1, 0x16a9e98c493a902b9502054edc03e7b22b7eac34345961bc8abced6bd147c8be, r)
                    let var7 := addmod(var5, var6, r)
                    let var8 := sub(r, var7)
                    let var9 := addmod(var4, var8, r)
                    let var10 := mulmod(f_8, var9, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_4 := calldataload(0x0484)
                    let var0 := 0x1
                    let var1 := sub(r, f_4)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_4, var2, r)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_0_prev_1 := calldataload(0x03e4)
                    let a_0 := calldataload(0x0324)
                    let var7 := addmod(a_0_prev_1, a_0, r)
                    let a_0_next_1 := calldataload(0x0364)
                    let var8 := sub(r, a_0_next_1)
                    let var9 := addmod(var7, var8, r)
                    let var10 := mulmod(var6, var9, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_4 := calldataload(0x0484)
                    let var0 := 0x1
                    let var1 := sub(r, f_4)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_4, var2, r)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_1_prev_1 := calldataload(0x03c4)
                    let a_1_next_1 := calldataload(0x0384)
                    let var7 := sub(r, a_1_next_1)
                    let var8 := addmod(a_1_prev_1, var7, r)
                    let var9 := mulmod(var6, var8, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var9, r)
                }
                {
                    let f_4 := calldataload(0x0484)
                    let var0 := 0x2
                    let var1 := sub(r, f_4)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_4, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_2 := calldataload(0x03a4)
                    let var7 := mulmod(var6, a_2, r)
                    let var8 := 0x1
                    let var9 := sub(r, a_2)
                    let var10 := addmod(var8, var9, r)
                    let var11 := mulmod(var7, var10, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var11, r)
                }
                {
                    let f_4 := calldataload(0x0484)
                    let var0 := 0x2
                    let var1 := sub(r, f_4)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_4, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_2 := calldataload(0x03a4)
                    let a_1 := calldataload(0x0344)
                    let a_0_next_1 := calldataload(0x0364)
                    let var7 := sub(r, a_0_next_1)
                    let var8 := addmod(a_1, var7, r)
                    let var9 := mulmod(a_2, var8, r)
                    let var10 := 0x1
                    let var11 := sub(r, a_2)
                    let var12 := addmod(var10, var11, r)
                    let a_0 := calldataload(0x0324)
                    let var13 := addmod(a_0, var7, r)
                    let var14 := mulmod(var12, var13, r)
                    let var15 := addmod(var9, var14, r)
                    let var16 := mulmod(var6, var15, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var16, r)
                }
                {
                    let f_4 := calldataload(0x0484)
                    let var0 := 0x2
                    let var1 := sub(r, f_4)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_4, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_2 := calldataload(0x03a4)
                    let a_0 := calldataload(0x0324)
                    let a_1_next_1 := calldataload(0x0384)
                    let var7 := sub(r, a_1_next_1)
                    let var8 := addmod(a_0, var7, r)
                    let var9 := mulmod(a_2, var8, r)
                    let var10 := 0x1
                    let var11 := sub(r, a_2)
                    let var12 := addmod(var10, var11, r)
                    let a_1 := calldataload(0x0344)
                    let var13 := addmod(a_1, var7, r)
                    let var14 := mulmod(var12, var13, r)
                    let var15 := addmod(var9, var14, r)
                    let var16 := mulmod(var6, var15, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var16, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, sub(r, mulmod(l_0, calldataload(0x0604), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let perm_z_last := calldataload(0x0664)
                    let eval := mulmod(mload(L_LAST_MPTR), addmod(mulmod(perm_z_last, perm_z_last, r), sub(r, perm_z_last), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0664), sub(r, calldataload(0x0644)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0624)
                    let rhs := calldataload(0x0604)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0404), mulmod(beta, calldataload(0x0544), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0324), mulmod(beta, calldataload(0x0564), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0344), mulmod(beta, calldataload(0x0584), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0424), mulmod(beta, calldataload(0x05a4), r), r), gamma, r), r)
                    mstore(0x00, mulmod(beta, mload(X_MPTR), r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0404), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0324), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0344), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0424), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0684)
                    let rhs := calldataload(0x0664)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x03a4), mulmod(beta, calldataload(0x05c4), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mulmod(beta, calldataload(0x05e4), r), r), gamma, r), r)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x03a4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mload(0x00), r), gamma, r), r)
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }

                pop(y)
                pop(delta)

                let quotient_eval := mulmod(quotient_eval_numer, mload(X_N_MINUS_1_INV_MPTR), r)
                mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            }

            // Compute quotient commitment
            {
                mstore(0x00, calldataload(LAST_QUOTIENT_X_CPTR))
                mstore(0x20, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x20)))
                let x_n := mload(X_N_MPTR)
                for
                    {
                        let cptr := sub(LAST_QUOTIENT_X_CPTR, 0x40)
                        let cptr_end := sub(FIRST_QUOTIENT_X_CPTR, 0x40)
                    }
                    lt(cptr_end, cptr)
                    {}
                {
                    success := ec_mul_acc(success, x_n)
                    success := ec_add_acc(success, calldataload(cptr), calldataload(add(cptr, 0x20)))
                    cptr := sub(cptr, 0x40)
                }
                mstore(QUOTIENT_X_MPTR, mload(0x00))
                mstore(QUOTIENT_Y_MPTR, mload(0x20))
            }

            // Compute pairing lhs and rhs
            {
                {
                    let x := mload(X_MPTR)
                    let omega := mload(OMEGA_MPTR)
                    let omega_inv := mload(OMEGA_INV_MPTR)
                    let x_pow_of_omega := mulmod(x, omega, r)
                    mstore(0x03a0, x_pow_of_omega)
                    mstore(0x0380, x)
                    x_pow_of_omega := mulmod(x, omega_inv, r)
                    mstore(0x0360, x_pow_of_omega)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    mstore(0x0340, x_pow_of_omega)
                }
                {
                    let mu := mload(MU_MPTR)
                    for
                        {
                            let mptr := 0x03c0
                            let mptr_end := 0x0440
                            let point_mptr := 0x0340
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            point_mptr := add(point_mptr, 0x20)
                        }
                    {
                        mstore(mptr, addmod(mu, sub(r, mload(point_mptr)), r))
                    }
                    let s
                    s := mload(0x03e0)
                    s := mulmod(s, mload(0x0400), r)
                    s := mulmod(s, mload(0x0420), r)
                    mstore(0x0440, s)
                    let diff
                    diff := mload(0x03c0)
                    mstore(0x0460, diff)
                    mstore(0x00, diff)
                    diff := mload(0x03c0)
                    diff := mulmod(diff, mload(0x03e0), r)
                    diff := mulmod(diff, mload(0x0420), r)
                    mstore(0x0480, diff)
                    diff := mload(0x03e0)
                    mstore(0x04a0, diff)
                    diff := mload(0x03c0)
                    diff := mulmod(diff, mload(0x03e0), r)
                    mstore(0x04c0, diff)
                }
                {
                    let point_1 := mload(0x0360)
                    let point_2 := mload(0x0380)
                    let point_3 := mload(0x03a0)
                    let coeff
                    coeff := addmod(point_1, sub(r, point_2), r)
                    coeff := mulmod(coeff, addmod(point_1, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, mload(0x03e0), r)
                    mstore(0x20, coeff)
                    coeff := addmod(point_2, sub(r, point_1), r)
                    coeff := mulmod(coeff, addmod(point_2, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, mload(0x0400), r)
                    mstore(0x40, coeff)
                    coeff := addmod(point_3, sub(r, point_1), r)
                    coeff := mulmod(coeff, addmod(point_3, sub(r, point_2), r), r)
                    coeff := mulmod(coeff, mload(0x0420), r)
                    mstore(0x60, coeff)
                }
                {
                    let point_2 := mload(0x0380)
                    let coeff
                    coeff := 1
                    coeff := mulmod(coeff, mload(0x0400), r)
                    mstore(0x80, coeff)
                }
                {
                    let point_0 := mload(0x0340)
                    let point_2 := mload(0x0380)
                    let point_3 := mload(0x03a0)
                    let coeff
                    coeff := addmod(point_0, sub(r, point_2), r)
                    coeff := mulmod(coeff, addmod(point_0, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, mload(0x03c0), r)
                    mstore(0xa0, coeff)
                    coeff := addmod(point_2, sub(r, point_0), r)
                    coeff := mulmod(coeff, addmod(point_2, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, mload(0x0400), r)
                    mstore(0xc0, coeff)
                    coeff := addmod(point_3, sub(r, point_0), r)
                    coeff := mulmod(coeff, addmod(point_3, sub(r, point_2), r), r)
                    coeff := mulmod(coeff, mload(0x0420), r)
                    mstore(0xe0, coeff)
                }
                {
                    let point_2 := mload(0x0380)
                    let point_3 := mload(0x03a0)
                    let coeff
                    coeff := addmod(point_2, sub(r, point_3), r)
                    coeff := mulmod(coeff, mload(0x0400), r)
                    mstore(0x0100, coeff)
                    coeff := addmod(point_3, sub(r, point_2), r)
                    coeff := mulmod(coeff, mload(0x0420), r)
                    mstore(0x0120, coeff)
                }
                {
                    success := batch_invert(success, 0, 0x0140, r)
                    let diff_0_inv := mload(0x00)
                    mstore(0x0460, diff_0_inv)
                    for
                        {
                            let mptr := 0x0480
                            let mptr_end := 0x04e0
                        }
                        lt(mptr, mptr_end)
                        { mptr := add(mptr, 0x20) }
                    {
                        mstore(mptr, mulmod(mload(mptr), diff_0_inv, r))
                    }
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x20), calldataload(0x03c4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0344), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0384), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x20), calldataload(0x03e4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0324), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0364), r), r)
                    mstore(0x04e0, r_eval)
                }
                {
                    let coeff := mload(0x80)
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0524), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, mload(QUOTIENT_EVAL_MPTR), r), r)
                    for
                        {
                            let mptr := 0x05e4
                            let mptr_end := 0x0524
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    for
                        {
                            let mptr := 0x0504
                            let mptr_end := 0x03e4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x03a4), r), r)
                    r_eval := mulmod(r_eval, mload(0x0480), r)
                    mstore(0x0500, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x0644), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0604), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0624), r), r)
                    r_eval := mulmod(r_eval, mload(0x04a0), r)
                    mstore(0x0520, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0664), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0120), calldataload(0x0684), r), r)
                    r_eval := mulmod(r_eval, mload(0x04c0), r)
                    mstore(0x0540, r_eval)
                }
                {
                    let sum := mload(0x20)
                    sum := addmod(sum, mload(0x40), r)
                    sum := addmod(sum, mload(0x60), r)
                    mstore(0x0560, sum)
                }
                {
                    let sum := mload(0x80)
                    mstore(0x0580, sum)
                }
                {
                    let sum := mload(0xa0)
                    sum := addmod(sum, mload(0xc0), r)
                    sum := addmod(sum, mload(0xe0), r)
                    mstore(0x05a0, sum)
                }
                {
                    let sum := mload(0x0100)
                    sum := addmod(sum, mload(0x0120), r)
                    mstore(0x05c0, sum)
                }
                {
                    for
                        {
                            let mptr := 0x00
                            let mptr_end := 0x80
                            let sum_mptr := 0x0560
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            sum_mptr := add(sum_mptr, 0x20)
                        }
                    {
                        mstore(mptr, mload(sum_mptr))
                    }
                    success := batch_invert(success, 0, 0x80, r)
                    let r_eval := mulmod(mload(0x60), mload(0x0540), r)
                    for
                        {
                            let sum_inv_mptr := 0x40
                            let sum_inv_mptr_end := 0x80
                            let r_eval_mptr := 0x0520
                        }
                        lt(sum_inv_mptr, sum_inv_mptr_end)
                        {
                            sum_inv_mptr := sub(sum_inv_mptr, 0x20)
                            r_eval_mptr := sub(r_eval_mptr, 0x20)
                        }
                    {
                        r_eval := mulmod(r_eval, mload(NU_MPTR), r)
                        r_eval := addmod(r_eval, mulmod(mload(sum_inv_mptr), mload(r_eval_mptr), r), r)
                    }
                    mstore(R_EVAL_MPTR, r_eval)
                }
                {
                    let nu := mload(NU_MPTR)
                    mstore(0x00, calldataload(0xa4))
                    mstore(0x20, calldataload(0xc4))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, calldataload(0x64), calldataload(0x84))
                    mstore(0x80, calldataload(0x01a4))
                    mstore(0xa0, calldataload(0x01c4))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, mload(QUOTIENT_X_MPTR), mload(QUOTIENT_Y_MPTR))
                    for
                        {
                            let mptr := 0x0c00
                            let mptr_end := 0x0940
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, mload(0x08c0), mload(0x08e0))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, mload(0x0880), mload(0x08a0))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, mload(0x0940), mload(0x0960))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, mload(0x0900), mload(0x0920))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0xe4), calldataload(0x0104))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0480), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), r)
                    mstore(0x80, calldataload(0x0124))
                    mstore(0xa0, calldataload(0x0144))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x04a0), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), r)
                    mstore(0x80, calldataload(0x0164))
                    mstore(0xa0, calldataload(0x0184))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x04c0), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, mload(G1_X_MPTR))
                    mstore(0xa0, mload(G1_Y_MPTR))
                    success := ec_mul_tmp(success, sub(r, mload(R_EVAL_MPTR)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x06a4))
                    mstore(0xa0, calldataload(0x06c4))
                    success := ec_mul_tmp(success, sub(r, mload(0x0440)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x06e4))
                    mstore(0xa0, calldataload(0x0704))
                    success := ec_mul_tmp(success, mload(MU_MPTR))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                    mstore(PAIRING_LHS_Y_MPTR, mload(0x20))
                    mstore(PAIRING_RHS_X_MPTR, calldataload(0x06e4))
                    mstore(PAIRING_RHS_Y_MPTR, calldataload(0x0704))
                }
            }

            // Random linear combine with accumulator
            if mload(HAS_ACCUMULATOR_MPTR) {
                mstore(0x00, mload(ACC_LHS_X_MPTR))
                mstore(0x20, mload(ACC_LHS_Y_MPTR))
                mstore(0x40, mload(ACC_RHS_X_MPTR))
                mstore(0x60, mload(ACC_RHS_Y_MPTR))
                mstore(0x80, mload(PAIRING_LHS_X_MPTR))
                mstore(0xa0, mload(PAIRING_LHS_Y_MPTR))
                mstore(0xc0, mload(PAIRING_RHS_X_MPTR))
                mstore(0xe0, mload(PAIRING_RHS_Y_MPTR))
                let challenge := mod(keccak256(0x00, 0x100), r)

                // [pairing_lhs] += challenge * [acc_lhs]
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_LHS_X_MPTR), mload(PAIRING_LHS_Y_MPTR))
                mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                mstore(PAIRING_LHS_Y_MPTR, mload(0x20))

                // [pairing_rhs] += challenge * [acc_rhs]
                mstore(0x00, mload(ACC_RHS_X_MPTR))
                mstore(0x20, mload(ACC_RHS_Y_MPTR))
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_RHS_X_MPTR), mload(PAIRING_RHS_Y_MPTR))
                mstore(PAIRING_RHS_X_MPTR, mload(0x00))
                mstore(PAIRING_RHS_Y_MPTR, mload(0x20))
            }

            // Perform pairing
            success := ec_pairing(
                success,
                mload(PAIRING_LHS_X_MPTR),
                mload(PAIRING_LHS_Y_MPTR),
                mload(PAIRING_RHS_X_MPTR),
                mload(PAIRING_RHS_Y_MPTR)
            )

            // Revert if anything fails
            if iszero(success) {
                revert(0x00, 0x00)
            }

            // Return 1 as result if everything succeeds
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}