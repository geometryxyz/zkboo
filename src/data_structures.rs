use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::Digest;

use crate::{
    commitment::{Blinding, Commitment},
    error::Error,
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    view::View, key::Key,
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
    pub fn commit<R: RngCore + CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
    ) -> Result<(Blinding<u64>, Commitment<D>), Error> {
        let blinding = Blinding(rng.next_u64());

        let commitment = Commitment::<D>::commit(&blinding, &self)?;
        Ok((blinding, commitment))
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
    D: Digest,
{
    pub outputs: Vec<Vec<GF2Word<T>>>,
    pub commitments: Vec<Commitment<D>>,
    pub views: Vec<View<T>>,
    pub keys: Vec<Key>,
    pub blinders: Vec<Blinding<u64>>,
}
