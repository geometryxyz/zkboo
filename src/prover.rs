use rand_core::{CryptoRng, RngCore};
use std::{
    fmt::Display,
    marker::PhantomData,
    ops::{BitAnd, BitXor},
};

use crate::{
    circuit::Circuit,
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    party::Party,
};

pub struct Prover<T>
where
    T: Copy + Display + BitAnd<Output = T> + BitXor<Output = T> + BitUtils + BytesInfo + GenRand,
{
    _word: PhantomData<T>,
}

impl<T> Prover<T>
where
    T: Copy + Display + BitAnd<Output = T> + BitXor<Output = T> + BitUtils + BytesInfo + GenRand,
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

    pub fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Vec<GF2Word<T>>,
        tapes: &[Vec<GF2Word<T>>; 3],
        circuit: &impl Circuit<T>,
    ) {
        let (mut p1, mut p2, mut p3) = Self::init_parties(rng, input, tapes);
        circuit.compute_23_decomposition(&mut p1, &mut p2, &mut p3);
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
