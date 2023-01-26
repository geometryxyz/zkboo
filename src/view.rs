use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use serde::{Deserialize, Serialize};

use crate::gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand};

#[derive(Default, Serialize, Deserialize)]
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
        }
    }

    pub fn send_msg(&mut self, msg: GF2Word<T>) {
        self.messages.push(msg);
    }
}
