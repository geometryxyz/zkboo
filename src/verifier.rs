use std::{
    fmt::Display,
    marker::PhantomData,
    ops::{BitAnd, BitXor},
};

use serde::Serialize;
use sha3::{Digest, digest::FixedOutputReset};

use crate::{
    circuit::{Circuit, TwoThreeDecOutput},
    data_structures::{Proof, PublicInput},
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand}, fs::SigmaFS, error::Error, data_structures::PartyExecution,
};

pub struct Verifier<T, D>
where
    T: Copy
        + Default
        + Display
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesInfo
        + GenRand,
    D: Digest + FixedOutputReset,
{
    _t: PhantomData<T>,
    _d: PhantomData<D>,
}

impl<T, D> Verifier<T, D>
where
    T: Copy
        + Default
        + Display
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesInfo
        + GenRand
        + Serialize,
    D: Digest + FixedOutputReset,
{
    pub fn verify(proof: &Proof<T, D>, circuit: &impl Circuit<T>, num_of_repetitions: usize) -> Result<(), Error> {
        let pi = PublicInput { outputs: &proof.outputs };

        // TODO: remove hardcoded seed
        let mut fs_oracle = SigmaFS::<D>::initialize(&[0u8]);
        fs_oracle.digest_public_data(&pi)?;
        fs_oracle.digest_prover_message(&proof.commitments)?;

        let opening_indices = fs_oracle.sample_trits(num_of_repetitions);

        Self::check_commitments(proof, &opening_indices);

        Ok(())
    }

    pub fn verify_repetition() {}

    fn check_commitments(proof: &Proof<T, D>, opening_indices: &Vec<usize>) {
        for (repetition, &party_index) in opening_indices.iter().enumerate() {
            let i0 = repetition * 3 + party_index;
            let i1 = repetition * 3 + ((party_index + 1) % 3);

            // check party i 
            let tape_i = &proof.tapes[2 * repetition];
            let view_i = &proof.views[2 * repetition];
            let pi_execution = PartyExecution { view: view_i, tape: &tape_i };
            let blinding_i = &proof.blinders[2 * repetition];

            let cm_i = &proof.commitments[i0];
            cm_i.verify_opening(blinding_i, &pi_execution).unwrap();

            // check party i + 1
            let tape_i1 = &proof.tapes[2 * repetition + 1];
            let view_i1 = &proof.views[2 * repetition + 1];
            let pi1_execution = PartyExecution { view: view_i1, tape: &tape_i1 };
            let blinding_i1 = &proof.blinders[2 * repetition + 1];

            let cm_i1 = &proof.commitments[i1];
            cm_i1.verify_opening(blinding_i1, &pi1_execution).unwrap();
        }
    }


    pub fn reconstruct(
        circuit: &impl Circuit<T>,
        circuit_output: &TwoThreeDecOutput<T>,
    ) -> Vec<GF2Word<T>> {
        let party_output_len = circuit.party_output_len();
        let (o1, o2, o3) = circuit_output;
        // TODO: introduce error here
        assert_eq!(o1.len(), party_output_len);
        assert_eq!(o2.len(), party_output_len);
        assert_eq!(o3.len(), party_output_len);
        let mut output = Vec::with_capacity(party_output_len);

        for i in 0..party_output_len {
            output.push(o1[i] ^ o2[i] ^ o3[i]);
        }

        output
    }
}
