use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use rand::{Rng, CryptoRng, RngCore};
use rand_core::CryptoRngCore;


#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Ciphertext {
    pub c1: RistrettoPoint,
    pub c2: RistrettoPoint,
}


#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Pi1Proof {
    pub a1: RistrettoPoint,
    pub a2: RistrettoPoint,
    pub b_com: RistrettoPoint,
    pub z_r: Scalar,
    pub z_s_h: Scalar,
}

pub struct Pi1PublicParams {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
    pub pk_alice: RistrettoPoint,
    pub pk_audit: RistrettoPoint
}

impl Pi1PublicParams {
    pub fn new(g: RistrettoPoint, h: RistrettoPoint, pk_alice: RistrettoPoint, pk_audit: RistrettoPoint) -> Self {
        Self { g, h, pk_alice, pk_audit } 
    }
}

pub fn prove_pi1<R: CryptoRngCore + ?Sized>(
    rng: &mut R,
    params: &Pi1PublicParams,
    s_h: Scalar,
    r: Scalar,
    ctxt_alice: &Ciphertext,
    ctxt_audit: &Ciphertext
) -> Pi1Proof {
    let a = Scalar::random(rng);
    let b = Scalar::random(rng);

    let a1 = a * params.pk_alice;
    let a2 = a * params.pk_audit;
    let b_com = a * params.g + b * params.h;

    let mut transcript = Transcript::new(b"Pi1");
    transcript.append_message(b"a1", a1.compress().as_bytes());
    transcript.append_message(b"a2", a2.compress().as_bytes());
    transcript.append_message(b"b_com", b_com.compress().as_bytes());
    transcript.append_message(b"c1_alice", ctxt_alice.c1.compress().as_bytes());
    transcript.append_message(b"c2_alice", ctxt_alice.c2.compress().as_bytes());
    transcript.append_message(b"c1_audit", ctxt_audit.c1.compress().as_bytes());
    transcript.append_message(b"c2_audit", ctxt_audit.c2.compress().as_bytes());

    let mut challenge_bytes = [0u8; 32];
    transcript.challenge_bytes(b"e", challenge_bytes.as_mut());
    let e = Scalar::from_bytes_mod_order(challenge_bytes);

    let z_r = a + e * r;
    let z_s_h = b + e * s_h;

    Pi1Proof { a1, a2, b_com, z_r, z_s_h }
}

pub fn verify_pi1(
    params: &Pi1PublicParams,
    proof: &Pi1Proof,
    ctxt_alice: &Ciphertext,
    ctxt_audit: &Ciphertext
) -> bool {
    let mut transcript = Transcript::new(b"Pi1");
    transcript.append_message(b"a1", proof.a1.compress().as_bytes());
    transcript.append_message(b"a2", proof.a2.compress().as_bytes());
    transcript.append_message(b"b_com", proof.b_com.compress().as_bytes());
    transcript.append_message(b"c1_alice", ctxt_alice.c1.compress().as_bytes());
    transcript.append_message(b"c2_alice", ctxt_alice.c2.compress().as_bytes());
    transcript.append_message(b"c1_audit", ctxt_audit.c1.compress().as_bytes());
    transcript.append_message(b"c2_audit", ctxt_audit.c2.compress().as_bytes());

    let mut challenge_bytes = [0u8; 32];
    transcript.challenge_bytes(b"e", challenge_bytes.as_mut());
    let e = Scalar::from_bytes_mod_order(challenge_bytes);

    let lhs_a1 = proof.z_r * params.pk_alice;
    let rhs_a1 = proof.a1 + (ctxt_alice.c1 * e);
    if (lhs_a1 != rhs_a1) {
        return false;
    }

    let lhs_a2 = proof.z_r * params.pk_audit;
    let rhs_a2 = proof.a2 + (ctxt_audit.c1 * e);
    if (lhs_a2 != rhs_a2) {
        return false;
    }

    let lhs_b_com = proof.z_r * params.g + proof.z_s_h * params.h;
    let rhs_b_com = proof.b_com + (e * ctxt_alice.c2); // ctxt_alice.c2 == ctxt_audit.c2

    lhs_b_com == rhs_b_com
}