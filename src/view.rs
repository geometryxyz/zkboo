use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use serde::{Deserialize, Serialize};

use crate::gf2_word::{BitUtils, BytesUitls, GF2Word, GenRand};

/// A party's `View` consists of:
/// - input: the party's initial share of the witness; and
/// - messages: the messages sent to the party.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct View<T>
where
    T: Copy
        + Default
        + Display
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesUitls
        + GenRand,
{
    offset: usize,
    pub input: Vec<GF2Word<T>>,
    pub messages: Vec<GF2Word<T>>,
}

impl<T> View<T>
where
    T: Copy
        + Default
        + Display
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesUitls
        + GenRand,
{
    pub fn new(input: Vec<GF2Word<T>>) -> Self {
        Self {
            input,
            messages: vec![],
            offset: 0,
        }
    }

    pub fn send_msg(&mut self, msg: GF2Word<T>) {
        self.messages.push(msg);
    }

    /// Read the message at the current `offset`.
    pub fn read_next(&mut self) -> GF2Word<T> {
        let msg_i = self.messages[self.offset];
        self.offset += 1;
        msg_i
    }
}
