use rand::{CryptoRng, RngCore, SeedableRng};

use crate::{
    gf2_word::{GF2Word, Value},
    key::Key,
    tape::Tape,
    view::View,
};

/// A party in the MPC protocol has a random tape and a `View`.
pub struct Party<T: Value> {
    pub tape: Tape<T>,
    pub view: View<T>,
}

impl<T: Value> Party<T> {
    pub fn new<TapeR: SeedableRng<Seed = Key> + RngCore + CryptoRng>(
        share: Vec<u8>,
        k: Key,
        tape_len: usize,
    ) -> Self {
        let tape = Tape::<T>::from_key::<TapeR>(k, tape_len);
        let view = View::new(share);

        Self { view, tape }
    }

    pub fn from_tape_and_view(view: View<T>, tape: Tape<T>) -> Self {
        Self { tape, view }
    }

    pub fn read_tape(&mut self) -> GF2Word<T> {
        self.tape.read_next()
    }

    pub fn read_view(&mut self) -> GF2Word<T> {
        self.view.read_next()
    }
}
