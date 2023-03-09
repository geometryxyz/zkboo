use std::{fmt::Display, ops::{BitAnd, BitXor}};

use crate::gf2_word::{GF2Word, BytesUitls, BitUtils, GenRand};

pub fn generic_parse<T>(bytes: &[u8], number_of_words: usize) -> Vec<GF2Word<T>>
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
    assert_eq!(bytes.len(), number_of_words * T::bytes_len());
    bytes.chunks(T::bytes_len()).map(|chunk| T::from_le_bytes(&chunk).into()).collect()
}