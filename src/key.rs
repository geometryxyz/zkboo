use rand::{CryptoRng, RngCore};

use crate::config::KEY_LEN;

pub type Key = [u8; KEY_LEN];
pub struct KeyManager {
    pub keys_bytes: Vec<u8>,
    num_of_accessible_keys: usize,
    offset: usize,
}

impl KeyManager {
    pub fn new<R: RngCore + CryptoRng>(num_repetitions: usize, rng: &mut R) -> Self {
        let mut keys_bytes = vec![0u8; 3 * num_repetitions * KEY_LEN];
        rng.fill_bytes(&mut keys_bytes);
        Self {
            keys_bytes,
            num_of_accessible_keys: 3 * num_repetitions,
            offset: 0,
        }
    }

    pub fn request_key(&mut self) -> Key {
        let offset = self.offset;
        if offset == self.num_of_accessible_keys {
            panic!("No more keys left!");
        }

        self.offset += 1;
        self.keys_bytes[offset * KEY_LEN..(offset + 1) * KEY_LEN]
            .try_into()
            .unwrap()
    }

    pub fn request_key_i(&self, pos: usize) -> Key {
        self.keys_bytes[pos * KEY_LEN..(pos + 1) * KEY_LEN]
            .try_into()
            .unwrap()
    }
}
