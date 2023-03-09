mod compression;
mod final_digest;
mod iv;
mod msg_schedule;
mod padding;

mod test_vectors;

use crate::{error::Error, gf2_word::GF2Word, party::Party};
use std::ops::Deref;
use std::iter;

use self::{
    compression::{mpc_compression, mpc_compression_verify},
    final_digest::{mpc_digest, mpc_digest_verify},
    msg_schedule::{mpc_msg_schedule, mpc_msg_schedule_verify},
};

/// TODO: Doc
#[derive(Debug)]
pub struct WorkingVariables {
    a: A,
    b: B,
    c: C,
    d: D,
    e: E,
    f: F,
    g: G,
    h: H,
}

impl WorkingVariables {
    pub fn to_vec(&self) -> Vec<GF2Word<u32>> {
        [
            (*self.a),
            (*self.b),
            (*self.c),
            (*self.d),
            (*self.e),
            (*self.f),
            (*self.g),
            (*self.h),
        ]
        .to_vec()
    }
}

// Working variables
#[derive(Debug, Clone, Copy)]
pub struct A(GF2Word<u32>);
impl Deref for A {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct B(GF2Word<u32>);
impl Deref for B {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[derive(Debug, Clone, Copy)]
pub struct C(GF2Word<u32>);
impl Deref for C {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[derive(Debug, Clone, Copy)]
pub struct D(GF2Word<u32>);
impl Deref for D {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[derive(Debug, Clone, Copy)]
pub struct E(GF2Word<u32>);
impl Deref for E {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[derive(Debug, Clone, Copy)]
pub struct F(GF2Word<u32>);
impl Deref for F {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[derive(Debug, Clone, Copy)]
pub struct G(GF2Word<u32>);
impl Deref for G {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct H(GF2Word<u32>);
impl Deref for H {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub fn mpc_sha256(
    input_p1: &[GF2Word<u32>; 16],
    input_p2: &[GF2Word<u32>; 16],
    input_p3: &[GF2Word<u32>; 16],
    p1: &mut Party<u32>,
    p2: &mut Party<u32>,
    p3: &mut Party<u32>,
) -> (Vec<GF2Word<u32>>, Vec<GF2Word<u32>>, Vec<GF2Word<u32>>) {
    let (msg_schedule_1, msg_schedule_2, msg_schedule_3) =
        mpc_msg_schedule(input_p1, input_p2, input_p3, p1, p2, p3);

    let (compression_output_1, compression_output_2, compression_output_3) = mpc_compression(
        &msg_schedule_1,
        &msg_schedule_2,
        &msg_schedule_3,
        p1,
        p2,
        p3,
    );

    mpc_digest(
        &compression_output_1.try_into().unwrap(),
        &compression_output_2.try_into().unwrap(),
        &compression_output_3.try_into().unwrap(),
        p1,
        p2,
        p3,
    )
}

pub fn mpc_sha256_verify(
    input_p: &[GF2Word<u32>; 16],
    input_p_next: &[GF2Word<u32>; 16],
    p: &mut Party<u32>,
    p_next: &mut Party<u32>,
) -> Result<(Vec<GF2Word<u32>>, Vec<GF2Word<u32>>), Error> {
    let (msg_schedule_p, msg_schedule_p_next) =
        mpc_msg_schedule_verify(input_p, input_p_next, p, p_next);

    let (compression_output_p, compression_output_p_next) =
        mpc_compression_verify(&msg_schedule_p, &msg_schedule_p_next, p, p_next)?;

    Ok(mpc_digest_verify(
        &compression_output_p.try_into().unwrap(),
        &compression_output_p_next.try_into().unwrap(),
        p,
        p_next,
    ))
}

// #[cfg(test)]
// mod test_sha256 {

//     use rand::{rngs::ThreadRng, thread_rng};
//     use rand_chacha::ChaCha20Rng;
//     use sha2::{Digest, Sha256};
//     use sha3::Keccak256;

//     use crate::{
//         circuit::{Circuit, Output},
//         error::Error,
//         gf2_word::GF2Word,
//         party::Party,
//         prover::Prover,
//         verifier::Verifier,
//     };

//     use super::*;

//     pub struct Sha256Circuit {
//         preimage: String,
//     }

//     impl Circuit<u32> for Sha256Circuit {
//         fn compute(&self, input: &[u8]) -> Vec<GF2Word<u32>> {
//             assert_eq!(input.len(), 0);
//             // create a Sha256 object
//             let mut hasher = Sha256::new();

//             // write input message
//             hasher.update(self.preimage.as_bytes());

//             // read hash digest and consume hasher
//             let digest = hasher.finalize().to_vec();

//             let mut res = Vec::with_capacity(8);
//             for i in 0..8 {
//                 let word = u32::from_be_bytes(digest[(4 * i)..(4 * i + 4)].try_into().unwrap());
//                 res.push(word.into())
//             }

//             res
//         }

//         fn compute_23_decomposition(
//             &self,
//             p1: &mut Party<u32>,
//             p2: &mut Party<u32>,
//             p3: &mut Party<u32>,
//         ) -> (Vec<GF2Word<u32>>, Vec<GF2Word<u32>>, Vec<GF2Word<u32>>) {

//             // let p1_words = generic_parse(&p1.view.input, self.party_input_len());
//             // let p2_words = generic_parse(&p2.view.input, self.party_input_len());
//             // let p3_words = generic_parse(&p3.view.input, self.party_input_len());
//             // call sha-padd gadget 

//             // in the loop 

//             let (o1, o2, o3) = mpc_sha256(
//                 &p1.view.input.clone().try_into().unwrap(),
//                 &p2.view.input.clone().try_into().unwrap(),
//                 &p3.view.input.clone().try_into().unwrap(),
//                 p1,
//                 p2,
//                 p3,
//             );
//             (o1.to_vec(), o2.to_vec(), o3.to_vec())
//         }

//         fn simulate_two_parties(
//             &self,
//             p: &mut Party<u32>,
//             p_next: &mut Party<u32>,
//         ) -> Result<(Output<u32>, Output<u32>), Error> {
//             assert_eq!(p.view.input.len(), self.party_input_len());
//             assert_eq!(p_next.view.input.len(), self.party_input_len());

//             let (o1, o2) = mpc_sha256_verify(
//                 &p.view.input.clone().try_into().unwrap(),
//                 &p_next.view.input.clone().try_into().unwrap(),
//                 p,
//                 p_next,
//             )?;

//             Ok((o1.to_vec(), o2.to_vec()))
//         }

//         fn party_input_len(&self) -> usize {
//             16
//         }

//         fn party_output_len(&self) -> usize {
//             8
//         }

//         fn num_of_mul_gates(&self) -> usize {
//             let msg_schedule = 3 * 48;
//             let compression = 9 * 64;
//             let digest = 8;

//             msg_schedule + compression + digest
//         }
//     }

//     #[test]
//     fn test_circuit() {
//         let mut rng = thread_rng();
//         const SIGMA: usize = 80;
//         let input: Vec<u8> = crate::gadgets::sha256::test_vectors::short::TEST_INPUT
//             .iter()
//             .map(|&vi| vi.to_le_bytes())
//             .flatten()
//             .collect();

//         let circuit = Sha256Circuit {
//             preimage: String::from("abc"),
//         };

//         let output = circuit.compute(&[]);
//         let expected_output = crate::gadgets::sha256::test_vectors::short::DIGEST_OUTPUT;
//         for (&word, &expected_word) in output.iter().zip(expected_output.iter()) {
//             assert_eq!(word.value, expected_word);
//         }

//         let proof = Prover::<u32, ChaCha20Rng, Keccak256>::prove::<ThreadRng, SIGMA>(
//             &mut rng, &input, &circuit, &output,
//         )
//         .unwrap();

//         Verifier::<u32, ChaCha20Rng, Keccak256>::verify(&proof, &circuit, &output).unwrap();
//     }
// }
