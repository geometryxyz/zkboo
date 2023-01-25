use std::marker::PhantomData;

use serde::Serialize;
use sha3::Digest;

use crate::error::Error;

const HASH_LEN: usize = 32;

pub struct Blinding<T: Serialize>(T);
impl<T: Serialize> AsRef<T> for Blinding<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

#[derive(Debug, PartialEq)]
pub struct Commitment<D: Digest> {
    data: [u8; HASH_LEN],
    _digest: PhantomData<D>
}

impl<D: Digest> Commitment<D> {
    pub fn commit<U: Serialize, T: Serialize>(blinding: &Blinding<U>, message: &T) -> Result<Self, Error> {
        let digest_len = <D as Digest>::output_size();
        if HASH_LEN != digest_len {
            return Err(Error::HashLenError(HASH_LEN, digest_len));
        }

        let blinding = bincode::serialize(blinding.as_ref()).map_err(|_| Error::SerializationError)?;
        let message = bincode::serialize(message).map_err(|_| Error::SerializationError)?;
    
        let mut hasher: D = Digest::new_with_prefix(&blinding);
        hasher.update(&message);
    
        // safe to unwrap since we check digest output is of right side
        let data = hasher.finalize().to_vec().try_into().unwrap();
        Ok(Self {
            data,
            _digest: PhantomData,
        })
    }  

    pub fn verify_opening<U: Serialize, T: Serialize>(&self, blinding: &Blinding<U>, message: &T) -> Result<bool, Error> {
        let blinding = bincode::serialize(blinding.as_ref()).map_err(|_| Error::SerializationError)?;
        let message = bincode::serialize(message).map_err(|_| Error::SerializationError)?;

        let mut hasher: D = Digest::new_with_prefix(&blinding);
        hasher.update(&message);

        let claimed_data: [u8; HASH_LEN] = hasher.finalize().to_vec().try_into().unwrap();
        Ok(claimed_data == self.data)
    }
}


#[cfg(test)]
mod commitment_tests {
    use sha3::{Keccak256, Keccak224};

    use super::{Blinding, Commitment};

    #[test]
    fn test_commitment() {
        let blinding = Blinding(String::from("I'm blinder"));
        let message = 5u32;

        let c = Commitment::<Keccak256>::commit(&blinding, &message).unwrap();
        assert!(c.verify_opening(&blinding, &message).unwrap())
    }

    #[test]
    #[should_panic]
    fn test_wrong_hash_len() {
        let blinding = Blinding(String::from("I'm blinder"));
        let message = 5u32;

        let _ = Commitment::<Keccak224>::commit(&blinding, &message).unwrap();
    }
}