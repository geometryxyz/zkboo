use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use rand::{CryptoRng, RngCore, SeedableRng};

use crate::{
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    key::Key,
};

/// A tape of values that can be read at its current `offset`.
pub struct Tape<T, const TAPE_LEN: usize>
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
    offset: usize,
    tape: [GF2Word<T>; TAPE_LEN],
}

impl<T, const TAPE_LEN: usize> Tape<T, TAPE_LEN>
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
    /// Initialise a tape with `len` entries using `key` as random seed.
    pub fn from_key<R: SeedableRng<Seed = Key> + RngCore + CryptoRng>(key: Key) -> Self {
        let mut rng = R::from_seed(key);
        let mut tape = vec![T::zero(); TAPE_LEN];

        let tape = (0..TAPE_LEN)
            .iter()
            .map(|| T::gen_rand(&mut rng).into())
            .try_into()
            .unwrap();

        Self { offset: 0, tape }
    }

    /// Read the next value on the tape.
    pub fn read_next(&mut self) -> GF2Word<T> {
        let ri = self.tape[self.offset];
        self.offset += 1;
        ri
    }
}
