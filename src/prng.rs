use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use rand::{CryptoRng, RngCore};

use crate::gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand};

/// function that just generates all the tapes up-front, faster then computing rng many times from PRNG
pub fn generate_tapes<T, R>(
    num_of_mul_gates: usize,
    num_of_repetitions: usize,
    rng: &mut R,
) -> [Vec<GF2Word<T>>; 3]
where
    T: Copy + Display + BitAnd<Output = T> + BitXor<Output = T> + BitUtils + BytesInfo + GenRand,
    R: RngCore + CryptoRng,
{
    let mut tape_p1 = Vec::with_capacity(num_of_repetitions * num_of_mul_gates);
    let mut tape_p2 = Vec::with_capacity(num_of_repetitions * num_of_mul_gates);
    let mut tape_p3 = Vec::with_capacity(num_of_repetitions * num_of_mul_gates);

    for _ in 0..(num_of_repetitions * num_of_mul_gates) {
        tape_p1.push(T::gen_rand(rng).into());
        tape_p2.push(T::gen_rand(rng).into());
        tape_p3.push(T::gen_rand(rng).into());

    }
    [tape_p1, tape_p2, tape_p3]
}
