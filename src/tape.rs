use std::{fmt::Display, ops::{BitAnd, BitXor}, marker::PhantomData};

use rand::{SeedableRng, RngCore, CryptoRng};

use crate::{gf2_word::{GF2Word, BitUtils, BytesInfo, GenRand}, prng::Key};

pub struct Tape<T, R> 
where
    T: Copy
        + Default
        + Display
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesInfo
        + GenRand,
    R: SeedableRng<Seed = Key> + RngCore + CryptoRng
{
    offset: usize,
    tape: Vec<GF2Word<T>>, 
    _r: PhantomData<R>
}

impl<T, R> Tape<T, R> 
where
    T: Copy
        + Default
        + Display
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesInfo
        + GenRand,
    R: SeedableRng<Seed = Key> + RngCore + CryptoRng
{
    pub fn from_key(key: Key, len: usize) -> Self {
        let mut rng = R::from_seed(key);
        let mut tape = Vec::with_capacity(len);

        for _ in 0..len {
            tape.push(T::gen_rand(&mut rng).into());
        }

        Self { offset: 0, tape, _r: PhantomData }
    }

    pub fn read_next(&mut self) -> GF2Word<T> {
        let ri = self.tape[self.offset];
        self.offset += 1;
        ri
    }
}