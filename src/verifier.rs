use std::{fmt::Debug, iter, marker::PhantomData};

use rand::{CryptoRng, RngCore, SeedableRng};

use rayon::prelude::*;
use sha3::{digest::FixedOutputReset, Digest};

use crate::{
    circuit::Circuit,
    commitment::Commitment,
    config::HASH_LEN,
    data_structures::{PartyExecution, Proof, PublicInput},
    error::Error,
    fs::SigmaFS,
    gf2_word::{GF2Word, Value},
    key::Key,
    num_of_repetitions_given_desired_security,
    party::Party,
    tape::Tape,
};

pub struct Verifier<T: Value, TapeR, D>(PhantomData<(T, TapeR, D)>)
where
    D: Digest + FixedOutputReset,
    TapeR: SeedableRng<Seed = Key> + RngCore + CryptoRng;

impl<T, TapeR, D> Verifier<T, TapeR, D>
where
    T: Value + PartialEq,
    TapeR: SeedableRng<Seed = Key> + RngCore + CryptoRng,
    D: Clone + Debug + Default + Digest + FixedOutputReset + Send,
{
    pub fn verify<const SIGMA: usize>(
        proofs: Vec<Proof<T, D, SIGMA>>,
        circuit: &impl Circuit<T>,
        public_output: &Vec<GF2Word<T>>,
    ) -> Result<(), Error> {
        #[derive(Clone)]
        struct Repetition<T: Value, D>
        where
            D: Debug + Default + Digest + FixedOutputReset + Clone + Send,
        {
            p1_output: Vec<GF2Word<T>>,
            p2_output: Vec<GF2Word<T>>,
            p3_output: Vec<GF2Word<T>>,
            p1_commitment: Commitment<D>,
            p2_commitment: Commitment<D>,
            p3_commitment: Commitment<D>,
            i: usize,
        }

        let num_of_repetitions = num_of_repetitions_given_desired_security(SIGMA);

        // Based on O3 and O5 of (https://eprint.iacr.org/2017/279.pdf)
        assert_eq!(proofs.len(), num_of_repetitions);

        let proof_trits: Vec<_> = proofs.iter().map(|p| p.claimed_trit).collect();

        let mut repetitions: Vec<_> = proofs
            .into_par_iter()
            .enumerate()
            .map(|(rep, proof)| {
                let (k_i0, k_i1) = proof.keys;
                let view_i1 = &proof.view;
                let mut p = Party::new::<TapeR>(
                    proof.party_input.clone(),
                    k_i0,
                    circuit.num_of_mul_gates(),
                );
                let mut p_next = Party::from_tape_and_view(
                    view_i1.clone(),
                    Tape::from_key::<TapeR>(k_i1, circuit.num_of_mul_gates()),
                );
                let (o0, o1) = circuit.simulate_two_parties(&mut p, &mut p_next).unwrap();
                let o2 = Self::derive_third_output(public_output, circuit, (&o0, &o1));

                /*
                    Based on O6 of (https://eprint.iacr.org/2017/279.pdf)
                    Instead of checking view consistency, full view is computed through simulation
                    then security comes from binding property of H used when committing
                */
                let view_i0 = &p.view;

                let pi0_execution = PartyExecution {
                    key: &k_i0,
                    view: view_i0,
                };

                // Based on O4 of (https://eprint.iacr.org/2017/279.pdf)
                let cm_i0 = pi0_execution.commit::<D>().unwrap();

                let pi1_execution = PartyExecution {
                    key: &k_i1,
                    view: view_i1,
                };

                // Based on O4 of (https://eprint.iacr.org/2017/279.pdf)
                let cm_i1 = pi1_execution.commit::<D>().unwrap();

                let cm_i2 = proof.commitment.clone();

                let (commitments, outputs) = match proof.claimed_trit {
                    0 => ((cm_i0, cm_i1, cm_i2), (o0, o1, o2)),
                    1 => ((cm_i2, cm_i0, cm_i1), (o2, o0, o1)),
                    2 => ((cm_i1, cm_i2, cm_i0), (o1, o2, o0)),
                    _ => panic!("Not trit"),
                };

                Repetition {
                    p1_output: outputs.0,
                    p2_output: outputs.1,
                    p3_output: outputs.2,
                    p1_commitment: commitments.0,
                    p2_commitment: commitments.1,
                    p3_commitment: commitments.2,
                    i: rep,
                }
            })
            .collect();
        repetitions.sort_by_key(|rep| rep.i);

        let outputs: Vec<_> = repetitions
            .iter()
            .flat_map(|r| {
                iter::once(r.p1_output.clone())
                    .chain(iter::once(r.p2_output.clone()))
                    .chain(iter::once(r.p3_output.clone()))
            })
            .collect();

        let all_commitments: Vec<_> = repetitions
            .iter()
            .flat_map(|r| {
                iter::once(r.p1_commitment.clone())
                    .chain(iter::once(r.p2_commitment.clone()))
                    .chain(iter::once(r.p3_commitment.clone()))
            })
            .collect();

        let pi = PublicInput {
            outputs: &outputs,
            public_output,
            hash_len: HASH_LEN,
            security_param: SIGMA,
        };

        // TODO: remove hardcoded seed
        let mut fs_oracle = SigmaFS::<D>::initialize(&[0u8]);
        fs_oracle.digest_public_data(&pi)?;
        fs_oracle.digest_prover_message(&all_commitments)?;

        let opening_indices = fs_oracle.sample_trits(num_of_repetitions);
        if opening_indices != proof_trits {
            return Err(Error::FiatShamirOutputsMatchingError);
        }

        Ok(())
    }

    pub fn derive_third_output(
        public_output: &[GF2Word<T>],
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
