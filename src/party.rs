use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use crate::{
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    view::View,
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
    tape_offset: usize,
    pub tape: Vec<GF2Word<T>>,
    pub view: View<T>,
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
    pub fn new(share: Vec<GF2Word<T>>, tape: Vec<GF2Word<T>>) -> Self {
        let view = View::new(share);

        Self {
            view,
            tape,
            tape_offset: 0,
        }
    }

    /*
        This function as agnostic to tape approach (full tape computed or PRNG )
    */
    pub fn read_tape(&mut self) -> GF2Word<T> {
        let ri = self.tape[self.tape_offset];
        self.tape_offset += 1;
        ri
    }
}
