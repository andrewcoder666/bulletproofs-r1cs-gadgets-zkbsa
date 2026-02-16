use crate::gadget_poseidon::{
    allocate_statics_for_prover, allocate_statics_for_verifier, PoseidonParams, SboxType,
};
use crate::gadget_vsmt_2::{vanilla_merkle_merkle_tree_verif_gadget, TreeDepth};
use crate::r1cs_utils::AllocatedScalar;
use bulletproofs::r1cs::{ConstraintSystem, Prover, Variable, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::traits::Identity;
use curve25519_dalek::{RistrettoPoint, Scalar};
use merlin::Transcript;
use rand::rngs::OsRng;
use rand::Rng;

pub type Pi2Proof = bulletproofs::r1cs::R1CSProof;

pub struct Pi2PublicParams {
    pub pedersen_gens: PedersenGens,
    pub bulletproof_gens: BulletproofGens,
    pub poseidon_params: PoseidonParams,
    pub root: Scalar,
    pub c2: RistrettoPoint,
}

pub struct Pi2Witness {
    pub pk_spend_scalar: Scalar,
    pub r: Scalar,
    pub s_h: Scalar,
    pub leaf_index: Scalar,
    pub merkle_path: Vec<Scalar>,
}

pub fn prove_pi2(
    witness: &Pi2Witness,
    public_params: &Pi2PublicParams,
) -> Result<Pi2Proof, bulletproofs::r1cs::R1CSError> {
    let mut prover_transcript = Transcript::new(b"Pi2");
    let mut prover = Prover::new(&public_params.pedersen_gens, &mut prover_transcript);

    // 1. Commit to (r, s_h) re-using c2 as commitment
    let (com_s_h, var_s_h) = prover.commit(witness.s_h, witness.r);

    // 2. Commit to pk_spend_scalar
    let pk_spend_blind = Scalar::random(&mut OsRng);
    let (com_pk_spend, var_pk_spend) = prover.commit(witness.pk_spend_scalar, pk_spend_blind);
    let pk_spend_alloc = AllocatedScalar {
        variable: var_pk_spend,
        assignment: Some(witness.pk_spend_scalar),
    };

    // 3. Allocate leaf index bits
    use crate::scalar_utils::get_bits;
    let leaf_index_bits = get_bits(&witness.leaf_index, TreeDepth)
        .iter()
        .take(TreeDepth)
        .map(|&b| {
            let val = Scalar::from(b as u8);
            let blind = Scalar::random(&mut OsRng);
            let (com, var) = prover.commit(val, blind);
            AllocatedScalar {
                variable: var,
                assignment: Some(val),
            }
        })
        .collect();

    // 4. Allocate Merkle proof nodes
    let proof_nodes: Vec<AllocatedScalar> = witness
        .merkle_path
        .iter()
        .map(|&node_val| {
            let blind = Scalar::random(&mut OsRng);
            let (com, var) = prover.commit(node_val, blind);
            AllocatedScalar {
                variable: var,
                assignment: Some(node_val),
            }
        })
        .collect();

    // 5. Allocate Poseidon statics
    let num_statics = 4;
    let statics = allocate_statics_for_prover(&mut prover, num_statics);

    // 6. Apply the Merkle verification gadget
    vanilla_merkle_merkle_tree_verif_gadget(
        &mut prover,
        TreeDepth,
        &public_params.root,
        pk_spend_alloc,
        leaf_index_bits,
        proof_nodes,
        statics,
        &public_params.poseidon_params,
    )?;

    // 7. Generate the proof
    let proof = prover.prove(&public_params.bulletproof_gens)?;
    Ok(proof)
}

pub fn verify_pi2(
    public_params: &Pi2PublicParams,
    proof: &Pi2Proof
) -> Result<(), bulletproofs::r1cs::R1CSError> {
    let mut verifier_transcript = Transcript::new(b"Pi2");
    let mut verifier = Verifier::new(&mut verifier_transcript);

    // 1. Commit to public inputs: c2
    let _var_s_r = verifier.commit(public_params.c2.compress());

    // 2. Allocate dummy variables for private inputs (witness)
    let dummy_pk_spend = AllocatedScalar {
        variable: verifier.commit(RistrettoPoint::identity().compress()),
        assignment: None,
    };

    let dummy_leaf_index_bits: Vec<AllocatedScalar> = (0..TreeDepth)
        .map(|_| AllocatedScalar {
            variable: verifier.commit(RistrettoPoint::identity().compress()),
            assignment: None,
        })
        .collect();

    let dummy_proof_nodes: Vec<AllocatedScalar> = (0..TreeDepth)
        .map(|_| AllocatedScalar {
            variable: verifier.commit(RistrettoPoint::identity().compress()),
            assignment: None,
        })
        .collect();

    let num_statics = 4;
    let statics = allocate_statics_for_verifier(&mut verifier, num_statics, &public_params.pedersen_gens);

    // 3. Apply the same Merkle verification gadget 
    vanilla_merkle_merkle_tree_verif_gadget(&mut verifier, TreeDepth, &public_params.root, dummy_pk_spend, dummy_leaf_index_bits, dummy_proof_nodes, statics, &public_params.poseidon_params)?;

    // 4. Verify the proof
    verifier.verify(proof, &public_params.pedersen_gens, &public_params.bulletproof_gens)
}