use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use rand::{SeedableRng, RngCore, CryptoRng};

use crate::{
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    view::View, tape::Tape, key::Key,
};

pub struct Party<T>
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
    pub tape: Tape<T>,
    pub view: View<T>
}

impl<T> Party<T>
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
    pub fn new<TapeR: SeedableRng<Seed = Key> + RngCore + CryptoRng>(share: Vec<GF2Word<T>>, k: Key, tape_len: usize) -> Self {
        let tape = Tape::<T>::from_key::<TapeR>(k, tape_len);
        let view = View::new(share);

        Self {
            view,
            tape,
        }
    }

    pub fn from_tape_and_view(view: View<T>, tape: Tape<T>) -> Self {
        Self {
            tape,
            view,
        }
    }

    /*
        This function as agnostic to tape approach (full tape computed or PRNG )
    */
    pub fn read_tape(&mut self) -> GF2Word<T> {
        self.tape.read_next()
    }

    pub fn read_view(&mut self) -> GF2Word<T> {
        self.view.read_next()
    }
}
