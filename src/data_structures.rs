use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use serde::{Deserialize, Serialize};
use sha3::Digest;

use crate::{
    commitment::{Blinding, Commitment},
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    view::View,
};

#[derive(Serialize)]
pub struct PublicInput<'a, T>
where
    T: Copy
        + Default
        + Display
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesInfo
        + GenRand
        + Serialize,
{
    pub outputs: &'a Vec<Vec<GF2Word<T>>>,
}

// TODO: add methods for computing proofs size, etc.
#[derive(Serialize, Deserialize)]
pub struct Proof<T, D>
where
    T: Copy
        + Default
        + Display
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesInfo
        + GenRand
        + Serialize,
    D: Digest,
{
    pub outputs: Vec<Vec<GF2Word<T>>>,
    pub commitments: Vec<Commitment<D>>,
    pub views: Vec<View<T>>,
    pub tapes: Vec<Vec<GF2Word<T>>>,
    pub blinders: Vec<Blinding<u64>>,
}
