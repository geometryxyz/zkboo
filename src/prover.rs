use rand::{thread_rng, SeedableRng};
use rand_core::{CryptoRng, RngCore};
use sha3::{digest::FixedOutputReset, Digest};
use std::{fmt::Debug, iter, marker::PhantomData};

use crate::multicore::IntoParallelIterator;

#[cfg(feature = "multicore")]
use crate::multicore::{IndexedParallelIterator, ParallelIterator};

use crate::{
    circuit::{Circuit, TwoThreeDecOutput},
    commitment::Commitment,
    config::HASH_LEN,
    data_structures::{PartyExecution, Proof, PublicInput},
    error::Error,
    fs::SigmaFS,
    gf2_word::{GF2Word, GenRand, Value},
    key::{Key, KeyManager},
    num_of_repetitions_given_desired_security,
    party::Party,
    view::View,
};

pub type Share<T> = Vec<GF2Word<T>>;

pub struct RepetitionOutput<T: Value> {
    pub party_outputs: TwoThreeDecOutput<T>,
    pub party_views: (View<T>, View<T>, View<T>),
}

pub struct Prover<T: Value, TapeR, D>(PhantomData<(T, TapeR, D)>)
where
    TapeR: SeedableRng<Seed = Key> + RngCore + CryptoRng,
    D: Debug + Default + Digest + FixedOutputReset + Send + Clone;

impl<T: Value, TapeR, D> Prover<T, TapeR, D>
where
    TapeR: SeedableRng<Seed = Key> + RngCore + CryptoRng,
    D: Debug + Default + Digest + FixedOutputReset + Send + Clone,
{
    pub fn share<R: RngCore + CryptoRng>(rng: &mut R, input: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let share_1: Vec<u8> = (0..input.len()).map(|_| u8::gen_rand(rng)).collect();
        let share_2: Vec<u8> = (0..input.len()).map(|_| u8::gen_rand(rng)).collect();

        let share_3: Vec<u8> = input
            .iter()
            .zip(share_1.iter())
            .zip(share_2.iter())
            .map(|((&i1, &i2), &i3)| i1 ^ i2 ^ i3)
            .collect();

        (share_1, share_2, share_3)
    }

    pub fn init_parties<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &[u8],
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
        input: &[u8],
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

    pub fn prove<R, const SIGMA: usize>(
        rng: &mut R,
        witness: &[u8],
        circuit: &impl Circuit<T>,
        public_output: &Vec<GF2Word<T>>,
    ) -> Result<Vec<Proof<T, D, SIGMA>>, Error>
    where
        R: RngCore + CryptoRng,
    {
        #[derive(Clone)]
        struct Repetition<T: Value, D>
        where
            D: Debug + Default + Digest + FixedOutputReset + Clone + Send,
        {
            p1_output: Vec<GF2Word<T>>,
            p2_output: Vec<GF2Word<T>>,
            p3_output: Vec<GF2Word<T>>,
            p1_view: View<T>,
            p2_view: View<T>,
            p3_view: View<T>,
            p1_commitment: Commitment<D>,
            p2_commitment: Commitment<D>,
            p3_commitment: Commitment<D>,
            i: usize,
        }

        impl<T: Value, D> Repetition<T, D>
        where
            D: Debug + Default + Digest + FixedOutputReset + Clone + Send,
        {
            fn view(&self, party_idx: u8) -> View<T> {
                if party_idx == 0 {
                    self.p1_view.clone()
                } else if party_idx == 1 {
                    self.p2_view.clone()
                } else if party_idx == 2 {
                    self.p3_view.clone()
                } else {
                    panic!()
                }
            }

            fn commitment(&self, party_idx: u8) -> Commitment<D> {
                if party_idx == 0 {
                    self.p1_commitment.clone()
                } else if party_idx == 1 {
                    self.p2_commitment.clone()
                } else if party_idx == 2 {
                    self.p3_commitment.clone()
                } else {
                    panic!()
                }
            }
        }

        let num_of_repetitions = num_of_repetitions_given_desired_security(SIGMA);
        let mut key_manager = KeyManager::new(num_of_repetitions, rng);

        let (k1s, (k2s, k3s)): (Vec<Key>, (Vec<Key>, Vec<Key>)) = (0..num_of_repetitions)
            .map(|_| {
                let k1 = key_manager.request_key();
                let k2 = key_manager.request_key();
                let k3 = key_manager.request_key();

                (k1, (k2, k3))
            })
            .unzip();

        let mut repetitions: Vec<_> = k1s
            .into_par_iter()
            .zip(k2s.into_par_iter())
            .zip(k3s.into_par_iter())
            .enumerate()
            .map(|(i, ((k1, k2), k3))| {
                let output =
                    Self::prove_repetition(&mut thread_rng(), witness, (k1, k2, k3), circuit);
                let (p1_output, p2_output, p3_output) = output.party_outputs;
                let (p1_view, p2_view, p3_view) = output.party_views;

                let p1_commitment = PartyExecution {
                    key: &k1,
                    view: &p1_view,
                }
                .commit()
                .unwrap();

                let p2_commitment = PartyExecution {
                    key: &k2,
                    view: &p2_view,
                }
                .commit()
                .unwrap();

                let p3_commitment = PartyExecution {
                    key: &k3,
                    view: &p3_view,
                }
                .commit()
                .unwrap();

                Repetition {
                    p1_output,
                    p2_output,
                    p3_output,
                    p1_view,
                    p2_view,
                    p3_view,
                    p1_commitment,
                    p2_commitment,
                    p3_commitment,
                    i,
                }
            })
            .collect();

        repetitions.sort_by_key(|rep| rep.i);
        // TODO: remove hardcoded seed
        let mut fs_oracle = SigmaFS::<D>::initialize(&[0u8]);

        let outputs: Vec<_> = repetitions
            .iter()
            .flat_map(|r| {
                iter::once(r.p1_output.clone())
                    .chain(iter::once(r.p2_output.clone()))
                    .chain(iter::once(r.p3_output.clone()))
            })
            .collect();

        let pi = PublicInput {
            outputs: &outputs,
            public_output,
            hash_len: HASH_LEN,
            security_param: SIGMA,
        };
        fs_oracle.digest_public_data(&pi)?;

        let all_commitments: Vec<_> = repetitions
            .iter()
            .flat_map(|r| {
                iter::once(r.p1_commitment.clone())
                    .chain(iter::once(r.p2_commitment.clone()))
                    .chain(iter::once(r.p3_commitment.clone()))
            })
            .collect();

        fs_oracle.digest_prover_message(&all_commitments)?;

        let opening_indices = fs_oracle.sample_trits(num_of_repetitions);

        let proofs = repetitions
            .iter()
            .zip(opening_indices)
            .enumerate()
            .map(|(repetition, (r, party_index))| {
                let claimed_trit = party_index;
                let i0 = party_index;
                let i1 = (party_index + 1) % 3;
                let i2 = (party_index + 2) % 3;
                let party_input = r.view(i0).input;
                let keys = (
                    key_manager.request_key_i(repetition * 3 + i0 as usize),
                    key_manager.request_key_i(repetition * 3 + i1 as usize),
                );
                let view = r.view(i1);
                let commitment = r.commitment(i2);

                Proof {
                    party_input,
                    commitment,
                    view,
                    keys,
                    claimed_trit,
                }
            })
            .collect();
        Ok(proofs)
    }
}
