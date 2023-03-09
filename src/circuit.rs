use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use crate::{
    error::Error,
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    party::Party,
};

pub trait Circuit<
    const PARTY_INPUT_LEN: usize,
    const PARTY_OUTPUT_LEN: usize,
    const NUM_MUL_GATES: usize,
    T,
> where
    T: Copy
        + Default
        + Display
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesInfo
        + GenRand,
{
    /// Computes circuit on 1 party
    fn compute(&self, input: &[GF2Word<T>; PARTY_INPUT_LEN]) -> [GF2Word<T>; PARTY_OUTPUT_LEN];

    /// Takes bytes input in little-endian order and converts it to suitable
    /// input for zkboo prover.
    fn prepare(&self, witness: &[u8]) -> [GF2Word<T>; PARTY_INPUT_LEN] {
        assert_eq!(witness.len(), PARTY_INPUT_LEN * T::bytes_len());

        witness
            .chunks(T::bytes_len())
            .map(|chunk| T::from_le_bytes(chunk).into())
            .collect()
            .try_into()
            .unwrap()
    }
    /// Decompose this circuit into 3 branches such that the values computed in
    /// 2 branches reveals no information about the input x.
    fn compute_23_decomposition(
        &self,
        p1: &mut Party<T, PARTY_INPUT_LEN, NUM_MUL_GATES>,
        p2: &mut Party<T, PARTY_INPUT_LEN, NUM_MUL_GATES>,
        p3: &mut Party<T, PARTY_INPUT_LEN, NUM_MUL_GATES>,
    ) -> (
        [GF2Word<T>; PARTY_OUTPUT_LEN],
        [GF2Word<T>; PARTY_OUTPUT_LEN],
        [GF2Word<T>; PARTY_OUTPUT_LEN],
    );
    fn simulate_two_parties(
        &self,
        p: &mut Party<T, PARTY_INPUT_LEN, NUM_MUL_GATES>,
        p_next: &mut Party<T, PARTY_INPUT_LEN, NUM_MUL_GATES>,
    ) -> Result<
        (
            [GF2Word<T>; PARTY_OUTPUT_LEN],
            [GF2Word<T>; PARTY_OUTPUT_LEN],
        ),
        Error,
    >;
}

#[cfg(test)]
mod circuit_tests {
    use std::{
        fmt::{Debug, Display},
        ops::{BitAnd, BitXor},
    };

    use rand::{rngs::ThreadRng, thread_rng};
    use rand_chacha::ChaCha20Rng;
    use sha3::Keccak256;

    use super::Circuit;
    use crate::{
        error::Error,
        gadgets::{mpc_and, mpc_and_verify, mpc_xor},
        gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
        party::Party,
        prover::Prover,
        verifier::Verifier,
    };

    // computes: (x1 ^ x2) & (x3 ^ x4) & x5
    #[derive(Clone, Copy)]
    struct SimpleCircuit1 {}

    const INPUT_LEN: usize = 5;
    const OUTPUT_LEN: usize = 1;
    const NUM_MUL_GATES: usize = 2;

    impl<T> Circuit<INPUT_LEN, OUTPUT_LEN, NUM_MUL_GATES, T> for SimpleCircuit1
    where
        T: Copy
            + Default
            + Display
            + Debug
            + PartialEq
            + BitAnd<Output = T>
            + BitXor<Output = T>
            + BitUtils
            + BytesInfo
            + GenRand,
    {
        fn compute(&self, input: &[GF2Word<T>; INPUT_LEN]) -> [GF2Word<T>; OUTPUT_LEN] {
            [(input[0] ^ input[1]) & (input[2] ^ input[3]) & input[4]]
        }

        fn compute_23_decomposition(
            &self,
            p1: &mut Party<T, INPUT_LEN, NUM_MUL_GATES>,
            p2: &mut Party<T, INPUT_LEN, NUM_MUL_GATES>,
            p3: &mut Party<T, INPUT_LEN, NUM_MUL_GATES>,
        ) -> (
            [GF2Word<T>; OUTPUT_LEN],
            [GF2Word<T>; OUTPUT_LEN],
            [GF2Word<T>; OUTPUT_LEN],
        ) {
            let (x1, x2, x3, x4, x5) = (
                p1.view.input[0],
                p1.view.input[1],
                p1.view.input[2],
                p1.view.input[3],
                p1.view.input[4],
            );
            let (y1, y2, y3, y4, y5) = (
                p2.view.input[0],
                p2.view.input[1],
                p2.view.input[2],
                p2.view.input[3],
                p2.view.input[4],
            );
            let (z1, z2, z3, z4, z5) = (
                p3.view.input[0],
                p3.view.input[1],
                p3.view.input[2],
                p3.view.input[3],
                p3.view.input[4],
            );

            let (a1, a2, a3) = mpc_xor((x1, x2), (y1, y2), (z1, z2));
            let (b1, b2, b3) = mpc_xor((x3, x4), (y3, y4), (z3, z4));

            let (ab1, ab2, ab3) = mpc_and((a1, b1), (a2, b2), (a3, b3), p1, p2, p3);

            let (o1, o2, o3) = mpc_and((ab1, x5), (ab2, y5), (ab3, z5), p1, p2, p3);

            ([o1], [o2], [o3])
        }

        fn simulate_two_parties(
            &self,
            p: &mut Party<T, INPUT_LEN, NUM_MUL_GATES>,
            p_next: &mut Party<T, INPUT_LEN, NUM_MUL_GATES>,
        ) -> Result<([GF2Word<T>; OUTPUT_LEN], [GF2Word<T>; OUTPUT_LEN]), Error> {
            let (x1, x2, x3, x4, x5) = (
                p.view.input[0],
                p.view.input[1],
                p.view.input[2],
                p.view.input[3],
                p.view.input[4],
            );

            let (y1, y2, y3, y4, y5) = (
                p_next.view.input[0],
                p_next.view.input[1],
                p_next.view.input[2],
                p_next.view.input[3],
                p_next.view.input[4],
            );

            let a1 = x1 ^ x2;
            let b1 = x3 ^ x4;

            let a2 = y1 ^ y2;
            let b2 = y3 ^ y4;

            let (ab1, ab2) = mpc_and_verify((a1, b1), (a2, b2), p, p_next)?;
            let (o1, o2) = mpc_and_verify((ab1, x5), (ab2, y5), p, p_next)?;

            Ok((vec![o1], vec![o2]))
        }
    }

    #[test]
    fn test_full_run() {
        let mut rng = thread_rng();
        const SIGMA: usize = 40;
        let input = vec![5u8, 4, 7, 2, 9];

        let circuit = SimpleCircuit1 {};
        let output = circuit.compute(&circuit.prepare(&input));

        let proof = Prover::<u32, ChaCha20Rng, Keccak256>::prove::<ThreadRng, SIGMA>(
            &mut rng, &input, &circuit, &output,
        )
        .unwrap();

        Verifier::<u32, ChaCha20Rng, Keccak256>::verify(&proof, &circuit, &output).unwrap();
    }
}
