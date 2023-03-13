mod compression;
mod final_digest;
mod iv;
mod msg_schedule;
mod padding;

mod test_vectors;

use crate::{error::Error, gf2_word::GF2Word, party::Party};
use std::ops::Deref;

use self::{
    compression::{mpc_compression, mpc_compression_verify},
    final_digest::{mpc_update_state, mpc_update_state_verify},
    msg_schedule::{mpc_msg_schedule, mpc_msg_schedule_verify},
};
pub use iv::init_iv;
pub use padding::padding;

/// TODO: Doc
#[derive(Debug, Clone, Copy)]
pub struct State {
    h0: GF2Word<u32>,
    h1: GF2Word<u32>,
    h2: GF2Word<u32>,
    h3: GF2Word<u32>,
    h4: GF2Word<u32>,
    h5: GF2Word<u32>,
    h6: GF2Word<u32>,
    h7: GF2Word<u32>,
}

impl State {
    pub fn to_vec(&self) -> Vec<GF2Word<u32>> {
        [
            self.h0, self.h1, self.h2, self.h3, self.h4, self.h5, self.h6, self.h7,
        ]
        .to_vec()
    }
}

impl From<Vec<GF2Word<u32>>> for State {
    fn from(value: Vec<GF2Word<u32>>) -> Self {
        assert_eq!(value.len(), 8);
        Self {
            h0: value[0],
            h1: value[1],
            h2: value[2],
            h3: value[3],
            h4: value[4],
            h5: value[5],
            h6: value[6],
            h7: value[7],
        }
    }
}

/// TODO: Doc
#[derive(Debug, Clone, Copy)]
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

impl From<Vec<GF2Word<u32>>> for WorkingVariables {
    fn from(value: Vec<GF2Word<u32>>) -> Self {
        assert_eq!(value.len(), 8);
        WorkingVariables {
            a: A(value[0]),
            b: B(value[1]),
            c: C(value[2]),
            d: D(value[3]),
            e: E(value[4]),
            f: F(value[5]),
            g: G(value[6]),
            h: H(value[7]),
        }
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

pub fn mpc_sha256_block(
    input_p1: &[GF2Word<u32>; 16],
    input_p2: &[GF2Word<u32>; 16],
    input_p3: &[GF2Word<u32>; 16],
    state: &(State, State, State),
    p1: &mut Party<u32>,
    p2: &mut Party<u32>,
    p3: &mut Party<u32>,
) -> (State, State, State) {
    let (msg_schedule_1, msg_schedule_2, msg_schedule_3) =
        mpc_msg_schedule(input_p1, input_p2, input_p3, p1, p2, p3);

    // Initialise working variables to current state
    let working_variables = (
        state.0.to_vec().into(),
        state.1.to_vec().into(),
        state.2.to_vec().into(),
    );

    let (working_variables_1, working_variables_2, working_variables_3) = mpc_compression(
        &msg_schedule_1,
        &msg_schedule_2,
        &msg_schedule_3,
        &working_variables,
        p1,
        p2,
        p3,
    );

    mpc_update_state(
        &working_variables_1.try_into().unwrap(),
        &working_variables_2.try_into().unwrap(),
        &working_variables_3.try_into().unwrap(),
        state,
        p1,
        p2,
        p3,
    )
}

pub fn mpc_sha256_block_verify(
    input_p: &[GF2Word<u32>; 16],
    input_p_next: &[GF2Word<u32>; 16],
    state: &(State, State),
    p: &mut Party<u32>,
    p_next: &mut Party<u32>,
) -> Result<(State, State), Error> {
    let (msg_schedule_p, msg_schedule_p_next) =
        mpc_msg_schedule_verify(input_p, input_p_next, p, p_next);

    // Initialise working variables to current state
    let working_variables = (state.0.to_vec().into(), state.1.to_vec().into());

    let (compression_output_p, compression_output_p_next) = mpc_compression_verify(
        &msg_schedule_p,
        &msg_schedule_p_next,
        &working_variables,
        p,
        p_next,
    )?;

    Ok(mpc_update_state_verify(
        &compression_output_p.try_into().unwrap(),
        &compression_output_p_next.try_into().unwrap(),
        state,
        p,
        p_next,
    ))
}

#[cfg(test)]
mod test_sha256 {

    use rand::{rngs::ThreadRng, thread_rng};
    use rand_chacha::ChaCha20Rng;
    use sha2::{Digest, Sha256};
    use sha3::Keccak256;

    use crate::{
        circuit::{Circuit, Output},
        error::Error,
        gadgets::sha256::padding::padding,
        gf2_word::GF2Word,
        party::Party,
        prover::Prover,
        verifier::Verifier,
    };

    use super::{iv::init_iv, *};

    pub struct Sha256Circuit {
        preimage: String,
    }

    impl Circuit<u32> for Sha256Circuit {
        fn compute(&self, input: &[u8]) -> Vec<GF2Word<u32>> {
            assert_eq!(input.len(), 0);
            // create a Sha256 object
            let mut hasher = Sha256::new();

            // write input message
            hasher.update(self.preimage.as_bytes());

            // read hash digest and consume hasher
            let digest = hasher.finalize().to_vec();

            let mut res = Vec::with_capacity(8);
            for i in 0..8 {
                let word = u32::from_be_bytes(digest[(4 * i)..(4 * i + 4)].try_into().unwrap());
                res.push(word.into())
            }

            res
        }

        fn compute_23_decomposition(
            &self,
            p1: &mut Party<u32>,
            p2: &mut Party<u32>,
            p3: &mut Party<u32>,
        ) -> (Vec<GF2Word<u32>>, Vec<GF2Word<u32>>, Vec<GF2Word<u32>>) {
            let p1_words = padding(&p1.view.input);
            let p2_words = padding(&p2.view.input);
            let p3_words = padding(&p3.view.input);

            // Initialize state
            let mut p1_state: State = init_iv().to_vec().into();
            let mut p2_state: State = init_iv().to_vec().into();
            let mut p3_state: State = init_iv().to_vec().into();

            // Process padded input chunk by chunk
            let iter_chunks = p1_words
                .chunks(16)
                .zip(p2_words.chunks(16))
                .zip(p3_words.chunks(16));

            for ((p1_words, p2_words), p3_words) in iter_chunks {
                (p1_state, p2_state, p3_state) = mpc_sha256_block(
                    &p1_words.try_into().unwrap(),
                    &p2_words.try_into().unwrap(),
                    &p3_words.try_into().unwrap(),
                    &(p1_state, p2_state, p3_state),
                    p1,
                    p2,
                    p3,
                );
            }

            (p1_state.to_vec(), p2_state.to_vec(), p3_state.to_vec())
        }

        fn simulate_two_parties(
            &self,
            p: &mut Party<u32>,
            p_next: &mut Party<u32>,
        ) -> Result<(Output<u32>, Output<u32>), Error> {
            let p_words = padding(&p.view.input);
            let p_next_words = padding(&p_next.view.input);

            // Initialize state
            let mut p_state: State = init_iv().to_vec().into();
            let mut p_next_state: State = init_iv().to_vec().into();

            // Process padded input chunk by chunk
            let iter_chunks = p_words.chunks(16).zip(p_next_words.chunks(16));

            for (p_words, p_next_words) in iter_chunks {
                (p_state, p_next_state) = mpc_sha256_block_verify(
                    &p_words.try_into().unwrap(),
                    &p_next_words.try_into().unwrap(),
                    &(p_state.to_vec().into(), p_next_state.to_vec().into()),
                    p,
                    p_next,
                )?;
            }

            Ok((p_state.to_vec(), p_next_state.to_vec()))
        }

        fn party_input_len(&self) -> usize {
            16
        }

        fn party_output_len(&self) -> usize {
            8
        }

        fn num_of_mul_gates(&self) -> usize {
            let num_chunks = padding(self.preimage.as_bytes()).len();

            let msg_schedule = 3 * 48;
            let compression = 9 * 64;
            let digest = 8;

            (msg_schedule + compression + digest) * num_chunks
        }
    }

    #[test]
    fn test_short_input() {
        let mut rng = thread_rng();
        const SIGMA: usize = 80;

        let preimage = String::from("abc");

        let circuit = Sha256Circuit {
            preimage: preimage.clone(),
        };

        let output = circuit.compute(&[]);
        let expected_output = crate::gadgets::sha256::test_vectors::short::DIGEST_OUTPUT;
        for (&word, &expected_word) in output.iter().zip(expected_output.iter()) {
            assert_eq!(word.value, expected_word);
        }

        let proof = Prover::<u32, ChaCha20Rng, Keccak256>::prove::<ThreadRng, SIGMA>(
            &mut rng,
            preimage.as_bytes(),
            &circuit,
            &output,
        )
        .unwrap();

        Verifier::<u32, ChaCha20Rng, Keccak256>::verify(&proof, &circuit, &output).unwrap();
    }

    #[test]
    fn test_long_input() {
        let mut rng = thread_rng();
        const SIGMA: usize = 80;

        let preimage = String::from("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");

        let circuit = Sha256Circuit {
            preimage: preimage.clone(),
        };

        let output = circuit.compute(&[]);
        let expected_output = crate::gadgets::sha256::test_vectors::long::DIGEST_OUTPUT;
        for (&word, &expected_word) in output.iter().zip(expected_output.iter()) {
            assert_eq!(word.value, expected_word);
        }

        let proof = Prover::<u32, ChaCha20Rng, Keccak256>::prove::<ThreadRng, SIGMA>(
            &mut rng,
            preimage.as_bytes(),
            &circuit,
            &output,
        )
        .unwrap();

        Verifier::<u32, ChaCha20Rng, Keccak256>::verify(&proof, &circuit, &output).unwrap();
    }
}
