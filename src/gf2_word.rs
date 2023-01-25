use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use rand_core::{CryptoRng, RngCore};

pub struct Bit(u8);

impl From<u8> for Bit {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

pub trait BytesInfo {
    fn to_bytes(&self) -> Vec<u8>;
    fn bytes_len() -> usize;
}

pub trait GenRand {
    fn gen_rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self;
}

pub trait BitUtils {
    fn get_bit(&self, pos: Self) -> Bit;
    fn set_bit(&self, pos: Self, bit: bool) -> Self;
}

impl BitUtils for u8 {
    fn get_bit(&self, pos: Self) -> Bit {
        let bit: u8 = ((self >> pos) & 1u8).try_into().unwrap();
        bit.into()
    }

    fn set_bit(&self, pos: Self, bit: bool) -> Self {
        let mask = 1u8 << pos;

        if bit {
            self | mask
        } else {
            self & !mask
        }
    }
}

impl BytesInfo for u8 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    fn bytes_len() -> usize {
        1
    }
}

impl GenRand for u8 {
    fn gen_rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut buff = vec![0u8; 1];
        rng.fill_bytes(&mut buff);
        buff[0]
    }
}

impl BitUtils for u32 {
    fn get_bit(&self, pos: Self) -> Bit {
        let bit: u8 = ((self >> pos) & 1u32).try_into().unwrap();
        bit.into()
    }

    fn set_bit(&self, pos: Self, bit: bool) -> Self {
        let mask = 1u32 << pos;

        if bit {
            self | mask
        } else {
            self & !mask
        }
    }
}

impl BytesInfo for u32 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
    fn bytes_len() -> usize {
        4
    }
}

impl GenRand for u32 {
    fn gen_rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        rng.next_u32()
    }
}

impl BitUtils for u64 {
    fn get_bit(&self, pos: Self) -> Bit {
        let bit: u8 = ((self >> pos) & 1u64).try_into().unwrap();
        bit.into()
    }

    fn set_bit(&self, pos: Self, bit: bool) -> Self {
        let mask = 1u64 << pos;

        if bit {
            self | mask
        } else {
            self & !mask
        }
    }
}

impl BytesInfo for u64 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
    fn bytes_len() -> usize {
        8
    }
}

impl GenRand for u64 {
    fn gen_rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        rng.next_u64()
    }
}

impl BitUtils for u128 {
    fn get_bit(&self, pos: Self) -> Bit {
        let bit: u8 = ((self >> pos) & 1u128).try_into().unwrap();
        bit.into()
    }

    fn set_bit(&self, pos: Self, bit: bool) -> Self {
        let mask = 1u128 << pos;

        if bit {
            self | mask
        } else {
            self & !mask
        }
    }
}

impl BytesInfo for u128 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
    fn bytes_len() -> usize {
        16
    }
}

impl GenRand for u128 {
    fn gen_rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let hi: u128 = rng.next_u64().try_into().unwrap();
        let low: u128 = rng.next_u64().try_into().unwrap();
        (hi << 64) | low
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GF2Word<T>
where
    T: Copy + Display + BitAnd<Output = T> + BitXor<Output = T> + BitUtils + BytesInfo + GenRand,
{
    pub value: T,
    pub size: usize,
}

impl<T> From<T> for GF2Word<T>
where
    T: Copy + Display + BitAnd<Output = T> + BitXor<Output = T> + BitUtils + BytesInfo + GenRand,
{
    fn from(value: T) -> Self {
        GF2Word::<T> {
            value,
            size: T::bytes_len() * 8,
        }
    }
}
impl<T> BitAnd for GF2Word<T>
where
    T: Copy + Display + BitAnd<Output = T> + BitXor<Output = T> + BitUtils + BytesInfo + GenRand,
{
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self {
            value: self.value & rhs.value,
            size: self.size,
        }
    }
}

impl<T> BitXor for GF2Word<T>
where
    T: Copy + Display + BitAnd<Output = T> + BitXor<Output = T> + BitUtils + BytesInfo + GenRand,
{
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        Self {
            value: self.value ^ rhs.value,
            size: self.size,
        }
    }
}

#[cfg(test)]
mod gf2_word_tests {
    use super::GF2Word;

    #[test]
    fn simple_and() {
        let v1 = 25u32;
        let v2 = 30u32;
        let x = GF2Word::<u32> {
            value: v1,
            size: 32,
        };

        let y = GF2Word::<u32> {
            value: v2,
            size: 32,
        };

        assert_eq!((x & y).value, v1 & v2);
    }

    #[test]
    fn simple_xor() {
        let v1 = 25u32;
        let v2 = 30u32;
        let x = GF2Word::<u32> {
            value: v1,
            size: 32,
        };

        let y = GF2Word::<u32> {
            value: v2,
            size: 32,
        };

        assert_eq!((x ^ y).value, v1 ^ v2);
    }
}
