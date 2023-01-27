use std::{
    fmt::Display,
    marker::PhantomData,
    ops::{BitAnd, BitXor},
};

use serde::Serialize;
use sha3::{digest::FixedOutputReset, Digest};

use crate::{
    circuit::Circuit,
    config::HASH_LEN,
    data_structures::PartyExecution,
    data_structures::{Proof, PublicInput},
    error::Error,
    fs::SigmaFS,
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    num_of_repetitions_given_desired_security,
    party::Party,
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
        + PartialEq
        + Serialize,
    D: Digest + FixedOutputReset,
{
    pub fn verify(
        proof: &Proof<T, D>,
        circuit: &impl Circuit<T>,
        security_param: usize,
        public_output: &Vec<GF2Word<T>>,
    ) -> Result<(), Error> {
        let num_of_repetitions = num_of_repetitions_given_desired_security(security_param);

        let pi = PublicInput {
            outputs: &proof.outputs,
            public_output,
            hash_len: HASH_LEN,
            security_param,
        };

        // TODO: remove hardcoded seed
        let mut fs_oracle = SigmaFS::<D>::initialize(&[0u8]);
        fs_oracle.digest_public_data(&pi)?;
        fs_oracle.digest_prover_message(&proof.commitments)?;

        let opening_indices = fs_oracle.sample_trits(num_of_repetitions);

        for (repetition, &party_index) in opening_indices.iter().enumerate() {
            Self::verify_repetition(repetition, party_index, proof, circuit, public_output)?;
        }

        Ok(())
    }

    pub fn verify_repetition(
        repetition: usize,
        party_index: usize,
        proof: &Proof<T, D>,
        circuit: &impl Circuit<T>,
        output: &Vec<GF2Word<T>>,
    ) -> Result<(), Error> {
        // check commitments
        let i0 = repetition * 3 + party_index;
        let i1 = repetition * 3 + ((party_index + 1) % 3);

        // check party i
        let tape_i = &proof.tapes[2 * repetition];
        let view_i = &proof.views[2 * repetition];
        let pi_execution = PartyExecution {
            view: view_i,
            tape: &tape_i,
        };
        let blinding_i = &proof.blinders[2 * repetition];

        let cm_i = &proof.commitments[i0];
        cm_i.verify_opening(blinding_i, &pi_execution).unwrap();

        // check party i + 1
        let tape_i1 = &proof.tapes[2 * repetition + 1];
        let view_i1 = &proof.views[2 * repetition + 1];
        let pi1_execution = PartyExecution {
            view: view_i1,
            tape: &tape_i1,
        };
        let blinding_i1 = &proof.blinders[2 * repetition + 1];

        let cm_i1 = &proof.commitments[i1];
        cm_i1.verify_opening(blinding_i1, &pi1_execution).unwrap();

        // reconstruct outputs
        let o1 = &proof.outputs[3 * repetition];
        let o2 = &proof.outputs[3 * repetition + 1];
        let o3 = &proof.outputs[3 * repetition + 2];
        if *output != Self::reconstruct(circuit, (o1, o2, o3)) {
            return Err(Error::OutputReconstructionError);
        }

        // verify actual circuit
        let mut p = Party::from_tape_and_view(view_i.clone(), tape_i.clone());
        let mut p_next = Party::from_tape_and_view(view_i1.clone(), tape_i1.clone());

        circuit.simulate_two_parties(&mut p, &mut p_next)?;

        Ok(())
    }

    pub fn reconstruct(
        circuit: &impl Circuit<T>,
        circuit_output: (&Vec<GF2Word<T>>, &Vec<GF2Word<T>>, &Vec<GF2Word<T>>),
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
