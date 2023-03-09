use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use rand::{CryptoRng, RngCore, SeedableRng};

use crate::{
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    key::Key,
    tape::Tape,
    view::View,
};

/// A party in the MPC protocol has a random tape and a `View`.
pub struct Party<T, const INPUT_LEN: usize, const TAPE_LEN: usize>
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
    pub tape: Tape<T, TAPE_LEN>,
    pub view: View<T, INPUT_LEN, TAPE_LEN>,
}

impl<T, const INPUT_LEN: usize, const TAPE_LEN: usize> Party<T, INPUT_LEN, TAPE_LEN>
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
    pub fn new<TapeR: SeedableRng<Seed = Key> + RngCore + CryptoRng>(
        share: Vec<GF2Word<T>>,
        k: Key,
        tape_len: usize,
    ) -> Self {
        let tape = Tape::<T, TAPE_LEN>::from_key::<TapeR>(k);
        let view = View::new(share);

        Self { view, tape }
    }

    pub fn from_tape_and_view(view: View<T, INPUT_LEN, TAPE_LEN>, tape: Tape<T, TAPE_LEN>) -> Self {
        Self { tape, view }
    }

    pub fn read_tape(&mut self) -> GF2Word<T> {
        self.tape.read_next()
    }

    pub fn read_view(&mut self) -> GF2Word<T> {
        self.view.read_next()
    }
}
