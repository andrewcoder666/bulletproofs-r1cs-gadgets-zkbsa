mod gadget_poseidon;
mod gadget_vsmt_2;
mod pi1;
mod pi2;
mod r1cs_utils;
mod scalar_utils;
mod poseidon_constants;
mod gadget_zero_nonzero;

use std::time::Instant;
use crate::pi1::{prove_pi1, verify_pi1, Ciphertext, Pi1PublicParams};
use crate::pi2::{prove_pi2, verify_pi2, Pi2PublicParams, Pi2Witness};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use gadget_poseidon::PoseidonParams;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Setup global parameters
    let pedersen_gens = PedersenGens::default();
    let bulletproof_gens = BulletproofGens::new(1024 * 1024, 1);
    let g_for_blinding = pedersen_gens.B_blinding;
    let h_for_message = pedersen_gens.B;
    let pk_alice = RistrettoPoint::random(&mut rng);
    let sk_audit = Scalar::random(&mut rng);
    let pk_audit = g_for_blinding * sk_audit;
    let pi1_params = Pi1PublicParams::new(g_for_blinding, h_for_message, pk_alice, pk_audit);


    // 2. Setup Merkle Tree
    let width = 6;
    let (full_b, full_e) = (4, 4);
    let partial_rounds = 140;
    let poseidon_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);
    let mut tree = crate::gadget_vsmt_2::VanillaSparseMerkleTree::new(&poseidon_params);

    // 3. Bob's keys
    let sk_spend_bob = Scalar::random(&mut rng);
    let pk_spend_bob = g_for_blinding * sk_spend_bob;
    let pk_spend_scalar = Scalar::from_bytes_mod_order(pk_spend_bob.compress().to_bytes());
    let leaf_index = Scalar::random(&mut rng);
    tree.update(leaf_index, pk_spend_scalar);
    let root = tree.root;

    // 4. Alice generates ciphertexts and proofs
    let s_h = Scalar::random(&mut rng);
    let r = Scalar::random(&mut rng);
    let ctxt_alice = Ciphertext {
        c1: pk_alice * r,
        c2: (g_for_blinding * r) + (h_for_message * s_h),
    };
    let ctxt_audit = Ciphertext {
        c1: pk_audit * r,
        c2: (g_for_blinding * r) + (h_for_message * s_h),
    };

    // 4.1 Alice generates π₁
    let timer1 = Instant::now();
    let pi1_proof = prove_pi1(&mut rng, &pi1_params, s_h, r, &ctxt_alice, &ctxt_audit);
    println!("pi1 proof time: {} ms", timer1.elapsed().as_secs_f64() * 1000.0);

    // 4.2 Alice generates π₂
    let mut merkle_proof_vec: Vec<Scalar> = Vec::new();
    let mut merkle_proof = Some(merkle_proof_vec);
    tree.get(leaf_index, &mut merkle_proof);
    let merkle_path = merkle_proof.unwrap();

    let pi2_witness = Pi2Witness {
        pk_spend_scalar,
        r,
        s_h,
        leaf_index,
        merkle_path,
    };

    let pi2_params = Pi2PublicParams {
        pedersen_gens,
        bulletproof_gens,
        poseidon_params,
        root,
        c2: ctxt_alice.c2,
    };
    let timer2 = Instant::now();
    let pi2_proof = prove_pi2(&pi2_witness, &pi2_params)?;
    println!("pi2 proof time: {} ms", timer2.elapsed().as_secs_f64() * 1000.0);

    // 5. Verifier checks π₁ and π₂
    let timer3 = Instant::now();
    assert!(verify_pi1(&pi1_params, &pi1_proof, &ctxt_alice, &ctxt_audit));
    println!("pi1 verify time: {} ms", timer3.elapsed().as_secs_f64() * 1000.0);

    let timer4 = Instant::now();
    verify_pi2(&pi2_params, &pi2_proof)?;
    println!("pi2 verify time: {} ms", timer4.elapsed().as_secs_f64() * 1000.0);

    Ok(())
}
