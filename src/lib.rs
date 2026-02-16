#![ allow( dead_code, unused_imports, non_upper_case_globals ) ]

extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;

pub mod scalar_utils;
pub mod r1cs_utils;
pub mod factors;
pub mod gadget_range_proof;
pub mod gadget_zero_nonzero;
pub mod gadget_vsmt_2;
pub mod gadget_vsmt_4;
mod poseidon_constants;
pub mod gadget_poseidon;
