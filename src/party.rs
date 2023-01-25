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
    T: Copy + Display + BitAnd<Output = T> + BitXor<Output = T> + BitUtils + BytesInfo + GenRand,
{
    pub tape: Vec<GF2Word<T>>,
    pub view: View<T>,
}

impl<T> Party<T>
where
    T: Copy + Display + BitAnd<Output = T> + BitXor<Output = T> + BitUtils + BytesInfo + GenRand,
{
    pub fn new(share: Vec<GF2Word<T>>, tape: Vec<GF2Word<T>>) -> Self {
        let view = View::new(share);

        Self { view, tape }
    }
}
