use serde::Serialize;
use sha3::{
    digest::{FixedOutputReset, OutputSizeUser},
    Digest,
};
use std::{
    fmt::Display,
    marker::PhantomData,
    ops::{BitAnd, BitXor},
};

use crate::{
    commitment::Commitment,
    data_structures::PublicInput,
    error::Error,
    gf2_word::{BitUtils, BytesInfo, GenRand},
};

pub struct SigmaProtocolStatelessFiatShamir<D: Clone + Digest> {
    _d: PhantomData<D>,
}

impl<D: Clone + Digest> SigmaProtocolStatelessFiatShamir<D> {
    pub fn sample_trits(seed: &[u8], public_data: &[u8], prover_msg: &[u8], r: usize) -> Vec<u8> {
        let with_prefix = |prefix: u8| {
            let mut hasher = D::new_with_prefix([prefix]);
            hasher.update(seed);
            hasher.update(public_data);
            hasher.update(prover_msg);

            hasher.finalize()
        };

        // local closure for which pos always < 8
        let get_bit = |x: u8, pos: usize| -> u8 { (x >> pos) & 1 };

        let mut trits = vec![0u8; r];

        let mut sampled: usize = 0;
        let mut prefix: u8 = 0;
        let mut pos = 0;

        let mut hash = with_prefix(prefix);

        while sampled < r {
            if pos >= <D as OutputSizeUser>::output_size() * 8 {
                prefix += 1;
                hash = with_prefix(prefix);
                pos = 0;
            }

            let b1 = get_bit(hash[(pos / 8)], pos % 8);
            let b2 = get_bit(hash[((pos + 1) / 8)], (pos + 1) % 8);

            let trit = (b1 << 1) | b2;
            if trit < 3 {
                trits[sampled] = trit;
                sampled += 1;
            }

            pos += 2;
        }

        trits
    }
}

pub struct SigmaFS<D: Digest + FixedOutputReset> {
    hasher: D,
}

impl<D: Default + Digest + FixedOutputReset> SigmaFS<D> {
    pub fn initialize(seed: &[u8]) -> Self {
        let hasher = Digest::new_with_prefix(seed);
        Self { hasher }
    }

    pub fn digest_public_data<T>(&mut self, pi: &PublicInput<T>) -> Result<(), Error>
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
        let data = bincode::serialize(pi).map_err(|_| Error::SerializationError)?;
        Digest::update(&mut self.hasher, &data);
        Ok(())
    }

    pub fn digest_prover_message(
        &mut self,
        single_run_commitments: &Vec<Commitment<D>>,
    ) -> Result<(), Error> {
        let data =
            bincode::serialize(single_run_commitments).map_err(|_| Error::SerializationError)?;
        Digest::update(&mut self.hasher, data);
        Ok(())
    }

    pub fn sample_trits(&mut self, r: usize) -> Vec<u8> {
        let mut hash = self.hasher.finalize_reset();

        // local closure for which pos always < 8
        let get_bit = |x: u8, pos: usize| -> u8 { (x >> pos) & 1 };

        let mut sampled: usize = 0;
        let mut pos = 0;

        let mut trits = vec![0u8; r];

        while sampled < r {
            if pos >= <D as OutputSizeUser>::output_size() * 8 {
                Digest::update(&mut self.hasher, &hash);
                hash = self.hasher.finalize_reset();
                pos = 0;
            }

            let b1 = get_bit(hash[(pos / 8)], pos % 8);
            let b2 = get_bit(hash[((pos + 1) / 8)], (pos + 1) % 8);

            let trit = (b1 << 1) | b2;
            if trit < 3 {
                trits[sampled] = trit;
                sampled += 1;
            }

            pos += 2;
        }

        trits
    }
}

#[cfg(test)]
mod test_fs {
    use super::SigmaProtocolStatelessFiatShamir;
    use sha3::Keccak256;

    #[test]
    fn test_stateless() {
        let seed = b"hello fs 1313e1";
        let public_data = b"this is public";
        let prover_msg = b"this from prover";
        let r = 137usize;

        let trits = SigmaProtocolStatelessFiatShamir::<Keccak256>::sample_trits(
            seed,
            public_data,
            prover_msg,
            r,
        );
        for trit in trits {
            assert!(trit == 0 || trit == 1 || trit == 2);
        }
    }
}
