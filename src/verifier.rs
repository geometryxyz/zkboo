use std::{
    fmt::Display,
    marker::PhantomData,
    ops::{BitAnd, BitXor},
};

use crate::{
    circuit::{Circuit, TwoThreeDecOutput},
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
};

pub struct Verifier<T>
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
    _t: PhantomData<T>,
}

impl<T> Verifier<T>
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
    pub fn reconstruct(
        circuit: &impl Circuit<T>,
        circuit_output: &TwoThreeDecOutput<T>,
    ) -> Vec<GF2Word<T>> {
        let party_output_len = circuit.party_output_len();
        let (o1, o2, o3) = circuit_output;
        // TODO: introduce error here
        assert_eq!(o1.len(), party_output_len);
        assert_eq!(o2.len(), party_output_len);
        assert_eq!(o3.len(), party_output_len);
        let mut output = Vec::with_capacity(party_output_len);

        for i in 0..party_output_len {
            output.push(o1[i] ^ o2[i] ^ o3[i]);
        }

        output
    }
}
