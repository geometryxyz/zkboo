// (a and b) xor (a and c) xor (b and c)
// = (a xor b) and (a xor c) xor a

use std::{
    fmt::{Debug, Display},
    ops::{BitAnd, BitXor},
};

use crate::{
    error::Error,
    gadgets::{mpc_and, mpc_and_verify},
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    party::Party,
};

fn maj<T>(a: T, b: T, c: T) -> T
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
    // (a and b) xor (a and c) xor (b and c)
    (a & b) ^ (a & c) ^ (b & c)
}

pub fn mpc_maj<T>(
    // a, b, c
    input_p1: (GF2Word<T>, GF2Word<T>, GF2Word<T>),
    input_p2: (GF2Word<T>, GF2Word<T>, GF2Word<T>),
    input_p3: (GF2Word<T>, GF2Word<T>, GF2Word<T>),
    p1: &mut Party<T>,
    p2: &mut Party<T>,
    p3: &mut Party<T>,
) -> (GF2Word<T>, GF2Word<T>, GF2Word<T>)
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
    // (a xor b)
    let a_xor_b_1 = input_p1.0 ^ input_p1.1;
    let a_xor_b_2 = input_p2.0 ^ input_p2.1;
    let a_xor_b_3 = input_p3.0 ^ input_p3.1;

    // (a xor c)
    let a_xor_c_1 = input_p1.0 ^ input_p1.2;
    let a_xor_c_2 = input_p2.0 ^ input_p2.2;
    let a_xor_c_3 = input_p3.0 ^ input_p3.2;

    // lhs = (a xor b) and (a xor c)
    let (lhs_1, lhs_2, lhs_3) = mpc_and(
        (a_xor_b_1, a_xor_c_1),
        (a_xor_b_2, a_xor_c_2),
        (a_xor_b_3, a_xor_c_3),
        p1,
        p2,
        p3,
    );

    // lhs xor a
    let output_p1 = lhs_1 ^ input_p1.0;
    let output_p2 = lhs_2 ^ input_p2.0;
    let output_p3 = lhs_3 ^ input_p3.0;

    (output_p1, output_p2, output_p3)
}

pub fn maj_verify<T>(
    input_p: (GF2Word<T>, GF2Word<T>, GF2Word<T>),
    input_p_next: (GF2Word<T>, GF2Word<T>, GF2Word<T>),
    p: &mut Party<T>,
    p_next: &mut Party<T>,
) -> Result<(GF2Word<T>, GF2Word<T>), Error>
where
    T: Copy
        + Debug
        + Default
        + Display
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesInfo
        + GenRand,
{
    // (a xor b)
    let a_xor_b_p = input_p.0 ^ input_p.1;
    let a_xor_b_p_next = input_p_next.0 ^ input_p_next.1;

    // (a xor c)
    let a_xor_c_p = input_p.0 ^ input_p.2;
    let a_xor_c_p_next = input_p_next.0 ^ input_p_next.2;

    // lhs = (a xor b) and (a xor c)
    let (lhs_p, lhs_p_next) = mpc_and_verify(
        (a_xor_b_p, a_xor_c_p),
        (a_xor_b_p_next, a_xor_c_p_next),
        p,
        p_next,
    )?;

    // lhs xor a
    let output_p = lhs_p ^ input_p.0;
    let output_p_next = lhs_p_next ^ input_p_next.0;

    Ok((output_p, output_p_next))
}

#[cfg(test)]
mod test_maj {
    use std::{
        fmt::{Debug, Display},
        marker::PhantomData,
        ops::{BitAnd, BitXor},
    };

    use rand::{rngs::ThreadRng, thread_rng};
    use rand_chacha::ChaCha20Rng;
    use sha3::Keccak256;

    use crate::{
        circuit::{Circuit, Output},
        error::Error,
        gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
        party::Party,
        prover::Prover,
        verifier::Verifier,
    };

    use super::*;

    pub struct MajCircuit<T>(PhantomData<T>)
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
            + GenRand;

    impl<T> MajCircuit<T>
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
        fn maj(&self, a: T, b: T, c: T) -> T {
            super::maj(a, b, c)
        }
    }

    impl<T> Circuit<T> for MajCircuit<T>
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
        fn compute(&self, input: &[GF2Word<T>]) -> Vec<GF2Word<T>> {
            assert_eq!(input.len(), 3);
            let res = self.maj(input[0].value, input[1].value, input[2].value);
            vec![res.into()]
        }

        fn compute_23_decomposition(
            &self,
            p1: &mut Party<T>,
            p2: &mut Party<T>,
            p3: &mut Party<T>,
        ) -> (Vec<GF2Word<T>>, Vec<GF2Word<T>>, Vec<GF2Word<T>>) {
            assert_eq!(p1.view.input.len(), 3);
            assert_eq!(p2.view.input.len(), 3);
            assert_eq!(p3.view.input.len(), 3);

            let input_p1 = (p1.view.input[0], p1.view.input[1], p1.view.input[2]);
            let input_p2 = (p2.view.input[0], p2.view.input[1], p2.view.input[2]);
            let input_p3 = (p3.view.input[0], p3.view.input[1], p3.view.input[2]);

            let (o1, o2, o3) = mpc_maj(input_p1, input_p2, input_p3, p1, p2, p3);
            (vec![o1], vec![o2], vec![o3])
        }

        fn simulate_two_parties(
            &self,
            p: &mut Party<T>,
            p_next: &mut Party<T>,
        ) -> Result<(Output<T>, Output<T>), Error> {
            assert_eq!(p.view.input.len(), 3);
            assert_eq!(p_next.view.input.len(), 3);

            let input_p = (p.view.input[0], p.view.input[1], p.view.input[2]);
            let input_p_next = (
                p_next.view.input[0],
                p_next.view.input[1],
                p_next.view.input[2],
            );

            let (o1, o2) = maj_verify(input_p, input_p_next, p, p_next)?;

            Ok((vec![o1], vec![o2]))
        }

        fn party_output_len(&self) -> usize {
            1
        }

        fn num_of_mul_gates(&self) -> usize {
            1
        }
    }

    #[test]
    fn test_circuit() {
        let mut rng = thread_rng();
        const SIGMA: usize = 80;
        let input: Vec<GF2Word<u32>> = [381321u32, 32131u32, 328131u32]
            .iter()
            .map(|&vi| vi.into())
            .collect();

        let circuit = MajCircuit::<u32>(PhantomData);

        let output = circuit.compute(&input);

        let proof = Prover::<u32, ChaCha20Rng, Keccak256>::prove::<ThreadRng, SIGMA>(
            &mut rng, &input, &circuit, &output,
        )
        .unwrap();

        Verifier::<u32, ChaCha20Rng, Keccak256>::verify(&proof, &circuit, &output).unwrap();
    }
}
