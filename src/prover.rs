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
    commitment::{Blinding, Commitment},
    data_structures::{Proof, PublicInput},
    error::Error,
    fs::SigmaFS,
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    party::Party,
    prng::generate_tapes,
    view::View,
};

// pairs of (tape, view)
#[derive(Serialize)]
pub struct PartyExecution<'a, T>
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
    tape: &'a [GF2Word<T>],
    view: &'a View<T>,
}

impl<'a, T> PartyExecution<'a, T>
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
{
    pub fn commit<R: RngCore + CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
    ) -> Result<(Blinding<u64>, Commitment<D>), Error> {
        let blinding = Blinding(rng.next_u64());

        let commitment = Commitment::<D>::commit(&blinding, &self)?;
        Ok((blinding, commitment))
    }
}

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

pub struct Prover<T>
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
    _word: PhantomData<T>,
}

impl<T> Prover<T>
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
        tapes: &[Vec<GF2Word<T>>; 3],
    ) -> (Party<T>, Party<T>, Party<T>) {
        let (share_1, share_2, share_3) = Self::share(rng, input);

        let p1 = Party::new(share_1, tapes[0].clone());
        let p2 = Party::new(share_2, tapes[1].clone());
        let p3 = Party::new(share_3, tapes[2].clone());

        (p1, p2, p3)
    }

    pub fn prove_repetition<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Vec<GF2Word<T>>,
        tapes: &[Vec<GF2Word<T>>; 3],
        circuit: &impl Circuit<T>,
    ) -> RepetitionOutput<T> {
        let (mut p1, mut p2, mut p3) = Self::init_parties(rng, input, tapes);
        let party_outputs = circuit.compute_23_decomposition(&mut p1, &mut p2, &mut p3);
        RepetitionOutput {
            party_outputs,
            party_views: (p1.view, p2.view, p3.view),
        }
    }

    pub fn prove<R: RngCore + CryptoRng, D: Digest + FixedOutputReset>(
        rng: &mut R,
        input: &Vec<GF2Word<T>>,
        circuit: &impl Circuit<T>,
        num_of_repetitions: usize,
    ) -> Result<Proof<T, D>, Error> {
        let num_of_mul_gates = circuit.num_of_mul_gates();

        // TODO: consider nicer tapes handling
        let tapes = generate_tapes::<T, R>(num_of_mul_gates, num_of_repetitions, rng);
        let tapes_0: Vec<&[GF2Word<T>]> = tapes[0]
            .iter()
            .as_slice()
            .chunks(num_of_mul_gates)
            .collect();
        let tapes_1: Vec<&[GF2Word<T>]> = tapes[1]
            .iter()
            .as_slice()
            .chunks(num_of_mul_gates)
            .collect();
        let tapes_2: Vec<&[GF2Word<T>]> = tapes[2]
            .iter()
            .as_slice()
            .chunks(num_of_mul_gates)
            .collect();

        let mut outputs = Vec::<Vec<GF2Word<T>>>::with_capacity(3 * num_of_repetitions);
        let mut commitments = Vec::<Commitment<D>>::with_capacity(3 * num_of_repetitions);
        let mut all_blinders = Vec::with_capacity(3 * num_of_repetitions);
        let mut all_views = Vec::with_capacity(3 * num_of_repetitions);

        for i in 0..num_of_repetitions {
            let tapes = [
                tapes_0[i].to_vec(),
                tapes_1[i].to_vec(),
                tapes_2[i].to_vec(),
            ];
            let repetition_output = Self::prove_repetition(rng, input, &tapes, circuit);

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
                tape: tapes_0[i],
                view: &all_views[views_len - 3],
            };
            let p2_execution = PartyExecution {
                tape: tapes_1[i],
                view: &all_views[views_len - 2],
            };
            let p3_execution = PartyExecution {
                tape: tapes_2[i],
                view: &all_views[views_len - 1],
            };

            for pi_execution in [p1_execution, p2_execution, p3_execution] {
                let (blinder, commitment) = pi_execution.commit(rng)?;
                all_blinders.push(blinder);
                commitments.push(commitment);
            }
        }

        let pi = PublicInput { outputs: &outputs };

        // TODO: remove hardcoded seed
        let mut fs_oracle = SigmaFS::<D>::initialize(&[0u8]);
        fs_oracle.digest_public_data(&pi)?;
        fs_oracle.digest_prover_message(&commitments)?;

        let opening_indices = fs_oracle.sample_trits(num_of_repetitions);

        let mut views = Vec::with_capacity(2 * num_of_repetitions);
        let mut blinders = Vec::with_capacity(2 * num_of_repetitions);

        for (repetition, &party_index) in opening_indices.iter().enumerate() {
            let i0 = repetition * 3 + party_index;
            let i1 = repetition * 3 + ((party_index + 1) % 3);

            views.push(std::mem::take(&mut all_views[i0]));
            views.push(std::mem::take(&mut all_views[i1]));

            blinders.push(std::mem::take(&mut all_blinders[i0]));
            blinders.push(std::mem::take(&mut all_blinders[i1]));
        }

        Ok(Proof {
            outputs,
            commitments,
            views,
            blinders,
        })
    }
}

#[cfg(test)]
mod prover_tests {
    use super::Prover;
    use rand::thread_rng;

    use crate::gf2_word::GF2Word;

    #[test]
    fn test_share() {
        let mut rng = thread_rng();

        let v1 = 25u32;
        let v2 = 30u32;

        let x = GF2Word::<u32> {
            value: v1,
            size: 32,
        };

        let y = GF2Word::<u32> {
            value: v2,
            size: 32,
        };

        let input = vec![x, y];

        let (share_1, share_2, share_3) = Prover::share(&mut rng, &input);

        let input_back: Vec<GF2Word<u32>> = share_1
            .iter()
            .zip(share_2.iter())
            .zip(share_3.iter())
            .map(|((&i1, &i2), &i3)| i1 ^ i2 ^ i3)
            .collect();
        assert_eq!(input, input_back);
    }
}
