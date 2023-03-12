use std::{
    fmt::{Debug, Display},
    ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr},
};

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

pub trait BytesUitls {
    fn to_bytes(&self) -> Vec<u8>;
    fn bytes_len() -> usize;
    fn from_le_bytes(le_bytes: &[u8]) -> Self;
}

pub trait GenRand {
    fn gen_rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self;
}

pub trait BitTrait:
    Copy
    + From<u8>
    + Shl<usize, Output = Self>
    + Shr<usize, Output = Self>
    + BitAnd
    + BitOr<Self, Output = Self>
    + BitAnd<Self, Output = Self>
    + Not<Output = Self>
    + Eq
    + PartialEq
{
}

pub trait Value:
    Copy
    + Debug
    + Default
    + Display
    + BitAnd<Output = Self>
    + BitXor<Output = Self>
    + BitUtils
    + BytesUitls
    + GenRand
    + Serialize
{
}

#[derive(Clone, Copy)]
pub struct Bit(u8);

impl Bit {
    pub fn inner(&self) -> bool {
        self.0 == 1
    }
}

impl BitAnd for Bit {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitXor for Bit {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

pub trait BitUtils: BitTrait {
    fn zero() -> Self {
        Self::from(0)
    }
    fn bits_len() -> usize;
    /// Get the value of a bit at position `pos`, where `pos`
    /// is little-endian. (e.g. pos = 0 returns LSB)
    fn get_bit(&self, pos: usize) -> Bit {
        // FIXME: Return Error::BitError
        assert!(pos < Self::bits_len());
        let bit = u8::from(((*self >> pos) & Self::from(1)) == Self::from(1));
        Bit(bit)
    }
    /// Set the value of a bit to `bit` at position `pos`.
    fn set_bit(&self, pos: usize, bit: bool) -> Self {
        let mask = Self::from(1) << pos;

        if bit {
            *self | mask
        } else {
            *self & !mask
        }
    }
    /// Rotate left by `n` bits.
    fn left_rotate(&self, n: usize) -> Self {
        assert!(n <= Self::bits_len());
        (*self << n) | (*self >> (Self::bits_len() - n))
    }
    /// Rotate right by `n` bits.
    fn right_rotate(&self, n: usize) -> Self {
        assert!(n <= Self::bits_len());
        (*self >> n) | (*self << (Self::bits_len() - n))
    }

    fn left_shift(&self, n: usize) -> Self {
        assert!(n <= Self::bits_len());
        *self << n
    }

    fn right_shift(&self, n: usize) -> Self {
        assert!(n <= Self::bits_len());
        *self >> n
    }
}

impl BitTrait for u8 {}
impl Value for u8 {}
impl BitUtils for u8 {
    fn bits_len() -> usize {
        Self::BITS as usize
    }
}

impl BytesUitls for u8 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    fn bytes_len() -> usize {
        1
    }
    fn from_le_bytes(le_bytes: &[u8]) -> Self {
        assert_eq!(le_bytes.len(), Self::bytes_len());
        Self::from_le_bytes(le_bytes.try_into().unwrap())
    }
}

impl GenRand for u8 {
    fn gen_rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut buff = vec![0u8; 1];
        rng.fill_bytes(&mut buff);
        buff[0]
    }
}

impl BitTrait for u32 {}
impl Value for u32 {}
impl BitUtils for u32 {
    fn bits_len() -> usize {
        Self::BITS as usize
    }
}

impl BytesUitls for u32 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    fn bytes_len() -> usize {
        4
    }

    fn from_le_bytes(le_bytes: &[u8]) -> Self {
        assert_eq!(le_bytes.len(), Self::bytes_len());
        Self::from_le_bytes(le_bytes.try_into().unwrap())
    }
}

impl GenRand for u32 {
    fn gen_rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        rng.next_u32()
    }
}

impl BitTrait for u64 {}
impl Value for u64 {}
impl BitUtils for u64 {
    fn bits_len() -> usize {
        Self::BITS as usize
    }
}

impl BytesUitls for u64 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
    fn bytes_len() -> usize {
        8
    }
    fn from_le_bytes(le_bytes: &[u8]) -> Self {
        assert_eq!(le_bytes.len(), Self::bytes_len());
        Self::from_le_bytes(le_bytes.try_into().unwrap())
    }
}

impl GenRand for u64 {
    fn gen_rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        rng.next_u64()
    }
}

impl BitTrait for u128 {}
impl Value for u128 {}
impl BitUtils for u128 {
    fn bits_len() -> usize {
        Self::BITS as usize
    }
}

impl BytesUitls for u128 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
    fn bytes_len() -> usize {
        16
    }
    fn from_le_bytes(le_bytes: &[u8]) -> Self {
        assert_eq!(le_bytes.len(), Self::bytes_len());
        Self::from_le_bytes(le_bytes.try_into().unwrap())
    }
}

impl GenRand for u128 {
    fn gen_rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let hi: u128 = rng.next_u64().try_into().unwrap();
        let low: u128 = rng.next_u64().try_into().unwrap();
        (hi << 64) | low
    }
}

/// A wrapper type for which we implement `BitAnd`, `BitXor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GF2Word<T: Value> {
    /// The value represented by this GF2 word
    pub value: T,
    /// Number of bits in `T`
    pub size: usize,
}

impl<T: Value> From<T> for GF2Word<T> {
    fn from(value: T) -> Self {
        GF2Word::<T> {
            value,
            size: T::bytes_len() * 8,
        }
    }
}
impl<T: Value> BitAnd for GF2Word<T> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self {
            value: self.value & rhs.value,
            size: self.size,
        }
    }
}

impl<T: Value> BitXor for GF2Word<T> {
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
