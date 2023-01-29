use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use serde::{Deserialize, Serialize};
use sha3::Digest;

use crate::{
    commitment::{Blinding, Commitment},
    error::Error,
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    key::Key,
    view::View,
};

#[derive(Serialize)]
pub struct PartyExecution<'a, T>
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
    pub key: &'a Key,
    pub view: &'a View<T>,
}

/*
   Based on: O4 of (https://eprint.iacr.org/2017/279.pdf)
*/
impl<'a, T> PartyExecution<'a, T>
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
    pub fn commit<D: Default + Digest>(&self) -> Result<Commitment<D>, Error> {
        let blinding = Blinding(self.key);

        let commitment = Commitment::<D>::commit(&blinding, self.view)?;
        Ok(commitment)
    }
}

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
    pub hash_len: usize,
    pub security_param: usize,
    pub public_output: &'a Vec<GF2Word<T>>,
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
    D: Default + Digest,
{
    pub party_inputs: Vec<Vec<GF2Word<T>>>,
    pub commitments: Vec<Commitment<D>>,
    pub views: Vec<View<T>>,
    pub keys: Vec<Key>,
    pub claimed_trits: Vec<u8>,
}
