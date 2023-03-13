use rand::{CryptoRng, RngCore, SeedableRng};

use crate::{
    gf2_word::{GF2Word, Value},
    key::Key,
};

/// A tape of values that can be read at its current `offset`.
pub struct Tape<T: Value> {
    offset: usize,
    tape: Vec<GF2Word<T>>,
}

impl<T: Value> Tape<T> {
    /// Initialise a tape with `len` entries using `key` as random seed.
    pub fn from_key<R: SeedableRng<Seed = Key> + RngCore + CryptoRng>(
        key: Key,
        len: usize,
    ) -> Self {
        let mut rng = R::from_seed(key);
        let mut tape = Vec::with_capacity(len);

        for _ in 0..len {
            tape.push(T::gen_rand(&mut rng).into());
        }

        Self { offset: 0, tape }
    }

    /// Read the next value on the tape.
    /// TODO: Return error if tape runs out of values.
    pub fn read_next(&mut self) -> GF2Word<T> {
        let ri = self.tape[self.offset];
        self.offset += 1;
        assert!(self.offset <= self.tape.len());
        ri
    }
}
