use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use serde::{Deserialize, Serialize};

use crate::gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand};

/// A party's `View` consists of:
/// - input: the party's initial share of the witness; and
/// - messages: the messages sent to the party.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct View<T, const INPUT_LEN: usize, const MSG_LEN: usize>
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
    read_offset: usize,
    write_offset: usize,
    pub input: [GF2Word<T>; INPUT_LEN],
    pub messages: [GF2Word<T>; MSG_LEN],
}

impl<T, const INPUT_LEN: usize, const MSG_LEN: usize> View<T, INPUT_LEN, MSG_LEN>
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
    pub fn new(input: [GF2Word<T>; INPUT_LEN]) -> Self {
        Self {
            input,
            messages: [T::zero().into(); MSG_LEN],
            read_offset: 0,
            write_offset: 0,
        }
    }

    pub fn send_msg(&mut self, msg: GF2Word<T>) {
        self.messages[self.write_offset] = msg;
        self.write_offset += 1;
    }

    /// Read the message at the current `offset`.
    pub fn read_next(&mut self) -> GF2Word<T> {
        let msg_i = self.messages[self.offset];
        self.read_offset += 1;
        msg_i
    }
}
