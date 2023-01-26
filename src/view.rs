use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use serde::{Deserialize, Serialize};

use crate::gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand};

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct View<T>
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
    pub input: Vec<GF2Word<T>>,
    messages: Vec<GF2Word<T>>,
}

impl<T> View<T>
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

    pub fn read_next(&mut self) -> GF2Word<T> {
        let msg_i = self.messages[self.offset];
        self.offset += 1;
        msg_i
    }
}
