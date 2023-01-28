use rand::SeedableRng;
use rand_core::{CryptoRng, RngCore};
use serde::Serialize;
use sha3::{digest::FixedOutputReset, Digest};
use std::{
    fmt::Display,
    marker::PhantomData,
    ops::{BitAnd, BitXor},
};

use crate::{
    circuit::{Circuit, TwoThreeDecOutput},
    commitment::Commitment,
    config::HASH_LEN,
    data_structures::{PartyExecution, Proof, PublicInput},
    error::Error,
    fs::SigmaFS,
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    key::{Key, KeyManager},
    num_of_repetitions_given_desired_security,
    party::Party,
    view::View,
};

pub struct RepetitionOutput<T>
where
    T: Copy
        + Default
        + Display
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesInfo
        + GenRand,
{
    pub party_outputs: TwoThreeDecOutput<T>,
    pub party_views: (View<T>, View<T>, View<T>),
}

pub struct Prover<T, TapeR, D>
where
    T: Copy
        + Default
        + Display
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesInfo
        + GenRand,
    TapeR: SeedableRng<Seed = Key> + RngCore + CryptoRng,
    D: Digest + FixedOutputReset,
{
    _word: PhantomData<T>,
    _tr: PhantomData<TapeR>,
    _d: PhantomData<D>,
}

impl<T, TapeR, D> Prover<T, TapeR, D>
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
    TapeR: SeedableRng<Seed = Key> + RngCore + CryptoRng,
    D: Digest + FixedOutputReset,
{
    pub fn share<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Vec<GF2Word<T>>,
    ) -> (Vec<GF2Word<T>>, Vec<GF2Word<T>>, Vec<GF2Word<T>>) {
        let share_1: Vec<GF2Word<T>> = (0..input.len()).map(|_| T::gen_rand(rng).into()).collect();
        let share_2: Vec<GF2Word<T>> = (0..input.len()).map(|_| T::gen_rand(rng).into()).collect();

        let share_3: Vec<_> = input
            .iter()
            .zip(share_1.iter())
            .zip(share_2.iter())
            .map(|((&i1, &i2), &i3)| i1 ^ i2 ^ i3)
            .collect();

        (share_1, share_2, share_3)
    }

    pub fn init_parties<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Vec<GF2Word<T>>,
        keys: (Key, Key, Key),
        tape_len: usize,
    ) -> (Party<T>, Party<T>, Party<T>) {
        let (share_1, share_2, share_3) = Self::share(rng, input);

        let p1 = Party::new::<TapeR>(share_1, keys.0, tape_len);
        let p2 = Party::new::<TapeR>(share_2, keys.1, tape_len);
        let p3 = Party::new::<TapeR>(share_3, keys.2, tape_len);

        (p1, p2, p3)
    }

    pub fn prove_repetition<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Vec<GF2Word<T>>,
        keys: (Key, Key, Key),
        circuit: &impl Circuit<T>,
    ) -> RepetitionOutput<T> {
        let (mut p1, mut p2, mut p3) =
            Self::init_parties(rng, input, keys, circuit.num_of_mul_gates());
        let party_outputs = circuit.compute_23_decomposition(&mut p1, &mut p2, &mut p3);
        RepetitionOutput {
            party_outputs,
            party_views: (p1.view, p2.view, p3.view),
        }
    }

    pub fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Vec<GF2Word<T>>,
        circuit: &impl Circuit<T>,
        security_param: usize,
        public_output: &Vec<GF2Word<T>>,
    ) -> Result<Proof<T, D>, Error> {
        let num_of_repetitions = num_of_repetitions_given_desired_security(security_param);

        let mut key_manager = KeyManager::new(num_of_repetitions, rng);

        let mut outputs = Vec::<Vec<GF2Word<T>>>::with_capacity(3 * num_of_repetitions);
        let mut commitments = Vec::<Commitment<D>>::with_capacity(3 * num_of_repetitions);
        let mut all_blinders = Vec::with_capacity(3 * num_of_repetitions);
        let mut all_views = Vec::with_capacity(3 * num_of_repetitions);

        for _ in 0..num_of_repetitions {
            let k1 = key_manager.request_key();
            let k2 = key_manager.request_key();
            let k3 = key_manager.request_key();

            let repetition_output = Self::prove_repetition(rng, input, (k1, k2, k3), circuit);

            // record all outputs
            outputs.push(repetition_output.party_outputs.0);
            outputs.push(repetition_output.party_outputs.1);
            outputs.push(repetition_output.party_outputs.2);

            // record all views
            all_views.push(repetition_output.party_views.0);
            all_views.push(repetition_output.party_views.1);
            all_views.push(repetition_output.party_views.2);

            let views_len = all_views.len();

            let p1_execution = PartyExecution {
                key: &k1,
                view: &all_views[views_len - 3],
            };
            let p2_execution = PartyExecution {
                key: &k2,
                view: &all_views[views_len - 2],
            };
            let p3_execution = PartyExecution {
                key: &k3,
                view: &all_views[views_len - 1],
            };

            for pi_execution in [p1_execution, p2_execution, p3_execution] {
                let (blinder, commitment) = pi_execution.commit(rng)?;
                all_blinders.push(blinder);
                commitments.push(commitment);
            }
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
        fs_oracle.digest_prover_message(&commitments)?;

        let opening_indices = fs_oracle.sample_trits(num_of_repetitions);

        let mut keys = Vec::<Key>::with_capacity(2 * num_of_repetitions);
        let mut views = Vec::with_capacity(2 * num_of_repetitions);
        let mut blinders = Vec::with_capacity(2 * num_of_repetitions);

        for (repetition, &party_index) in opening_indices.iter().enumerate() {
            let i0 = repetition * 3 + party_index;
            let i1 = repetition * 3 + ((party_index + 1) % 3);

            views.push(std::mem::take(&mut all_views[i0]));
            views.push(std::mem::take(&mut all_views[i1]));

            blinders.push(std::mem::take(&mut all_blinders[i0]));
            blinders.push(std::mem::take(&mut all_blinders[i1]));

            keys.push(key_manager.request_key_i(i0));
            keys.push(key_manager.request_key_i(i1));
        }

        Ok(Proof {
            outputs,
            commitments,
            views,
            keys,
            blinders,
        })
    }
}
