use std::{
    fmt::Display,
    ops::{BitAnd, BitXor}, marker::PhantomData,
};

use rand::{CryptoRng, RngCore, SeedableRng};

use crate::{gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand}, config::KEY_LEN};

/// function that just generates all the tapes up-front, faster then computing rng many times from PRNG
pub fn generate_tapes<T, R>(
    num_of_mul_gates: usize,
    num_of_repetitions: usize,
    rng: &mut R,
) -> [Vec<GF2Word<T>>; 3]
where
    T: Copy
        + Default
        + Display
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesInfo
        + GenRand,
    R: RngCore + CryptoRng,
{
    let mut tape_p1 = Vec::with_capacity(num_of_repetitions * num_of_mul_gates);
    let mut tape_p2 = Vec::with_capacity(num_of_repetitions * num_of_mul_gates);
    let mut tape_p3 = Vec::with_capacity(num_of_repetitions * num_of_mul_gates);

    for _ in 0..(num_of_repetitions * num_of_mul_gates) {
        tape_p1.push(T::gen_rand(rng).into());
        tape_p2.push(T::gen_rand(rng).into());
        tape_p3.push(T::gen_rand(rng).into());
    }
    [tape_p1, tape_p2, tape_p3]
}

pub type Key = [u8; KEY_LEN];
pub struct KeyManager<R> 
where
    R: RngCore + CryptoRng,
{
    pub keys_bytes: Vec<u8>,
    num_of_accessible_keys: usize, 
    offset: usize, 
    _r: PhantomData<R>,
}

impl<R> KeyManager<R>  
where
    R: RngCore + CryptoRng,
{
    pub fn new(num_repetitions: usize, rng: &mut R) -> Self {
        let mut keys_bytes = vec![0u8; 3 * num_repetitions * KEY_LEN];
        rng.fill_bytes(&mut keys_bytes);
        Self { keys_bytes, num_of_accessible_keys: 3 * num_repetitions, offset: 0, _r: PhantomData }
    }

    pub fn request_key(&mut self) -> Key {
        let offset = self.offset; 
        if offset == self.num_of_accessible_keys {
            panic!("No more keys left!");
        }

        self.offset += 1; 
        self.keys_bytes[offset * KEY_LEN..(offset + 1) * KEY_LEN].try_into().unwrap()
    }
}

/// function that just generates all the tapes up-front, faster then computing rng many times from PRNG
pub fn generate_tapes_from_keys<T, R>(
    num_of_mul_gates: usize,
    k1: R::Seed,
    k2: R::Seed,
    k3: R::Seed,
) -> (Vec<GF2Word<T>>, Vec<GF2Word<T>>, Vec<GF2Word<T>>)
where
    T: Copy
        + Default
        + Display
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesInfo
        + GenRand,
    R: SeedableRng + RngCore + CryptoRng,
{
    let mut rng_1 = R::from_seed(k1);
    let mut rng_2 = R::from_seed(k2);
    let mut rng_3 = R::from_seed(k3);

    let mut tape_p1 = Vec::with_capacity(num_of_mul_gates);
    let mut tape_p2 = Vec::with_capacity(num_of_mul_gates);
    let mut tape_p3 = Vec::with_capacity(num_of_mul_gates);

    for _ in 0..num_of_mul_gates {
        tape_p1.push(T::gen_rand(&mut rng_1).into());
        tape_p2.push(T::gen_rand(&mut rng_2).into());
        tape_p3.push(T::gen_rand(&mut rng_3).into());
    }

    (tape_p1, tape_p2, tape_p3)
}

#[cfg(test)]
mod test_tapes {
    use super::{generate_tapes_from_keys, KeyManager};
    use rand::thread_rng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn all_tapes() {
        let mut rng = thread_rng();

        let num_repetitions = 20; 
        let num_mul_gates = 10;

        let mut key_manager = KeyManager::new(num_repetitions, &mut rng);

        for _ in 0..num_repetitions {
            let k1 = key_manager.request_key();
            let k2 = key_manager.request_key();
            let k3 = key_manager.request_key();

            let _ = generate_tapes_from_keys::<u8, ChaCha20Rng>(num_mul_gates, k1, k2, k3);
        }
    }
}
