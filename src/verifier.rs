use std::{
    fmt::Display,
    marker::PhantomData,
    ops::{BitAnd, BitXor},
};

use rand::{CryptoRng, RngCore, SeedableRng};
use serde::Serialize;
use sha3::{digest::FixedOutputReset, Digest};

use crate::{
    circuit::Circuit,
    config::HASH_LEN,
    data_structures::{Proof, PublicInput, PartyExecution},
    error::Error,
    fs::SigmaFS,
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    key::Key,
    num_of_repetitions_given_desired_security,
    party::Party,
    tape::Tape, commitment::Commitment,
};

pub struct Verifier<T, TapeR, D>
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
    TapeR: SeedableRng<Seed = Key> + RngCore + CryptoRng,
{
    _t: PhantomData<T>,
    _tr: PhantomData<TapeR>,
    _d: PhantomData<D>,
}

impl<T, TapeR, D> Verifier<T, TapeR, D>
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
    TapeR: SeedableRng<Seed = Key> + RngCore + CryptoRng,
    D: Clone + Default + Digest + FixedOutputReset,
{
    pub fn verify(
        proof: &Proof<T, D>,
        circuit: &impl Circuit<T>,
        security_param: usize,
        public_output: &Vec<GF2Word<T>>,
    ) -> Result<(), Error> {
        let num_of_repetitions = num_of_repetitions_given_desired_security(security_param);

        // Based on O3 and O5 of (https://eprint.iacr.org/2017/279.pdf)
        assert_eq!(proof.party_inputs.len(), num_of_repetitions);
        assert_eq!(proof.commitments.len(), num_of_repetitions);
        assert_eq!(proof.views.len(), num_of_repetitions);
        assert_eq!(proof.claimed_trits.len(), num_of_repetitions);
        assert_eq!(proof.keys.len(), 2 * num_of_repetitions);

        let mut all_commitments = Vec::<Commitment<D>>::with_capacity(3 * num_of_repetitions);
        let mut outputs = Vec::<Vec<GF2Word<T>>>::with_capacity(3 * num_of_repetitions);

        for (repetition, &party_index) in proof.claimed_trits.iter().enumerate() {
            let k_i0 = proof.keys[2 * repetition];
            let mut p = Party::new::<TapeR>(proof.party_inputs[repetition].clone(), k_i0, circuit.num_of_mul_gates());

            let k_i1 = proof.keys[2 * repetition + 1];
            let view_i1 = &proof.views[repetition];

            let tape_i1 = Tape::from_key::<TapeR>(k_i1, circuit.num_of_mul_gates());
            let mut p_next = Party::from_tape_and_view(view_i1.clone(), tape_i1);

            let (o0, o1) = circuit.simulate_two_parties(&mut p, &mut p_next)?;
            let o2 = Self::derive_third_output(public_output, circuit, (&o0, &o1));

            /*
                Based on O6 of (https://eprint.iacr.org/2017/279.pdf)
                Instead of checking view consistency, full view is computed through simulation 
                then security comes from binding property of H used when committing 
            */ 
            let view_i0 = &p.view;

            let pi0_execution = PartyExecution {
                key: &k_i0, 
                view: &view_i0
            };

            // Based on O4 of (https://eprint.iacr.org/2017/279.pdf)
            let cm_i0 = pi0_execution.commit::<D>()?;

            let pi1_execution = PartyExecution {
                key: &k_i1, 
                view: &view_i1
            };

            // Based on O4 of (https://eprint.iacr.org/2017/279.pdf)
            let cm_i1 = pi1_execution.commit::<D>()?;

            let cm_i2 = &proof.commitments[repetition];

            match party_index {
                0 => {
                    all_commitments.push(cm_i0);
                    all_commitments.push(cm_i1);
                    all_commitments.push(cm_i2.clone());

                    outputs.push(o0);
                    outputs.push(o1);
                    outputs.push(o2);

                }
                1 => {
                    all_commitments.push(cm_i2.clone());
                    all_commitments.push(cm_i0);
                    all_commitments.push(cm_i1);

                    outputs.push(o2);
                    outputs.push(o0);
                    outputs.push(o1);
                }
                2 => {
                    all_commitments.push(cm_i1);
                    all_commitments.push(cm_i2.clone());
                    all_commitments.push(cm_i0);

                    outputs.push(o1);
                    outputs.push(o2);
                    outputs.push(o0);
                }
                _ => panic!("Not trit")
            };
        }

        let pi = PublicInput {
            outputs: &outputs,
            public_output,
            hash_len: HASH_LEN,
            security_param,
        };

        // TODO: remove hardcoded seed
        let mut fs_oracle = SigmaFS::<D>::initialize(&[0u8]);
        fs_oracle.digest_public_data(&pi)?;
        fs_oracle.digest_prover_message(&all_commitments)?;

        let opening_indices = fs_oracle.sample_trits(num_of_repetitions);
        if opening_indices != proof.claimed_trits {
            return Err(Error::FiatShamirOutputsMatchingError)
        }

        Ok(())
    }

    pub fn derive_third_output(
        public_output: &Vec<GF2Word<T>>,
        circuit: &impl Circuit<T>,
        circuit_simulation_output: (&Vec<GF2Word<T>>, &Vec<GF2Word<T>>),
    ) -> Vec<GF2Word<T>> {
        let party_output_len = circuit.party_output_len();
        let (o1, o2) = circuit_simulation_output;

        // TODO: introduce error here
        assert_eq!(o1.len(), party_output_len);
        assert_eq!(o2.len(), party_output_len);

        let mut derived_output = Vec::with_capacity(party_output_len);

        for i in 0..party_output_len {
            derived_output.push(o1[i] ^ o2[i] ^ public_output[i]);
        }

        derived_output
    }
}
