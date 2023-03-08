use crate::{
    gadgets::{
        add_mod::{add_mod_verify, adder, mpc_add_mod},
        Party,
    },
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
};
use std::{
    fmt::{Debug, Display},
    ops::{BitAnd, BitXor},
};

/// s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
fn s0<T>(i: usize, w: &[GF2Word<T>]) -> GF2Word<T>
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
    (w[i - 15].value.right_rotate(7)
        ^ w[i - 15].value.right_rotate(18)
        ^ w[i - 15].value.right_shift(3))
    .into()
}

/// s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
fn s1<T>(i: usize, w: &[GF2Word<T>]) -> GF2Word<T>
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
    (w[i - 2].value.right_rotate(17)
        ^ w[i - 2].value.right_rotate(19)
        ^ w[i - 2].value.right_shift(10))
    .into()
}

pub fn msg_schedule<T>(input: &[GF2Word<T>; 16]) -> [GF2Word<T>; 64]
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
    let mut w = input[..].to_vec();

    // extend words
    for i in 16..64 {
        /*
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        */

        let s_0 = s0(i, &w);
        let s_1 = s1(i, &w);

        let lhs = adder(w[i - 16].value, s_0.value);
        let rhs = adder(w[i - 7].value, s_1.value);

        w.push(adder(lhs, rhs).into());
    }

    w.try_into().unwrap()
}

/// Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
pub fn mpc_msg_schedule<T>(
    input_p1: &[GF2Word<T>; 16],
    input_p2: &[GF2Word<T>; 16],
    input_p3: &[GF2Word<T>; 16],
    p1: &mut Party<T>,
    p2: &mut Party<T>,
    p3: &mut Party<T>,
) -> ([GF2Word<T>; 64], [GF2Word<T>; 64], [GF2Word<T>; 64])
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
    let mut w_1 = input_p1[..].to_vec();
    let mut w_2 = input_p2[..].to_vec();
    let mut w_3 = input_p3[..].to_vec();

    // extend words
    for i in 16..64 {
        /*
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;

            Each addition is using 1 gate multiplication
            which means that we have 3 multiplications
        */

        let (lhs_1, lhs_2, lhs_3) = mpc_add_mod(
            (w_1[i - 16], s0(i, &w_1)),
            (w_2[i - 16], s0(i, &w_2)),
            (w_3[i - 16], s0(i, &w_3)),
            p1,
            p2,
            p3,
        );

        let (rhs_1, rhs_2, rhs_3) = mpc_add_mod(
            (w_1[i - 7], s1(i, &w_1)),
            (w_2[i - 7], s1(i, &w_2)),
            (w_3[i - 7], s1(i, &w_3)),
            p1,
            p2,
            p3,
        );

        let (o1, o2, o3) = mpc_add_mod((lhs_1, rhs_1), (lhs_2, rhs_2), (lhs_3, rhs_3), p1, p2, p3);

        w_1.push(o1);
        w_2.push(o2);
        w_3.push(o3);
    }

    (
        w_1.try_into().unwrap(),
        w_2.try_into().unwrap(),
        w_3.try_into().unwrap(),
    )
}

pub fn mpc_msg_schedule_verify<T>(
    input_p: &[GF2Word<T>; 16],
    input_p_next: &[GF2Word<T>; 16],
    p: &mut Party<T>,
    p_next: &mut Party<T>,
) -> ([GF2Word<T>; 64], [GF2Word<T>; 64])
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
    let mut w = input_p[..].to_vec();
    let mut w_next = input_p_next[..].to_vec();

    // extend words
    for i in 16..64 {
        /*
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;

            Each addition is using 1 gate multiplication
            which means that we have 3 multiplications
        */

        let (lhs, lhs_next) = add_mod_verify(
            (w[i - 16], s0(i, &w)),
            (w_next[i - 16], s0(i, &w_next)),
            p,
            p_next,
        );

        let (rhs, rhs_next) = add_mod_verify(
            (w[i - 7], s1(i, &w)),
            (w_next[i - 7], s1(i, &w_next)),
            p,
            p_next,
        );

        let (o, o_next) = add_mod_verify((lhs, rhs), (lhs_next, rhs_next), p, p_next);

        w.push(o);
        w_next.push(o_next);
    }

    (w.try_into().unwrap(), w_next.try_into().unwrap())
}

#[cfg(test)]
mod test_msg_schedule {
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

    pub struct MsgScheduleCircuit<T>(PhantomData<T>)
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

    impl<T> Circuit<T> for MsgScheduleCircuit<T>
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
            assert_eq!(input.len(), 16);
            let res = msg_schedule(input.try_into().unwrap());
            res.to_vec()
        }

        fn compute_23_decomposition(
            &self,
            p1: &mut Party<T>,
            p2: &mut Party<T>,
            p3: &mut Party<T>,
        ) -> (Vec<GF2Word<T>>, Vec<GF2Word<T>>, Vec<GF2Word<T>>) {
            assert_eq!(p1.view.input.len(), 16);
            assert_eq!(p2.view.input.len(), 16);
            assert_eq!(p3.view.input.len(), 16);

            let (o1, o2, o3) = mpc_msg_schedule(
                &p1.view.input.clone().try_into().unwrap(),
                &p2.view.input.clone().try_into().unwrap(),
                &p3.view.input.clone().try_into().unwrap(),
                p1,
                p2,
                p3,
            );
            (o1.to_vec(), o2.to_vec(), o3.to_vec())
        }

        fn simulate_two_parties(
            &self,
            p: &mut Party<T>,
            p_next: &mut Party<T>,
        ) -> Result<(Output<T>, Output<T>), Error> {
            assert_eq!(p.view.input.len(), 16);
            assert_eq!(p_next.view.input.len(), 16);

            let (o1, o2) = mpc_msg_schedule_verify(
                &p.view.input.clone().try_into().unwrap(),
                &p_next.view.input.clone().try_into().unwrap(),
                p,
                p_next,
            );

            Ok((o1.to_vec(), o2.to_vec()))
        }

        fn party_output_len(&self) -> usize {
            64
        }

        fn num_of_mul_gates(&self) -> usize {
            3 * 48
        }
    }

    #[test]
    fn test_circuit() {
        let mut rng = thread_rng();
        const SIGMA: usize = 80;
        let input: Vec<GF2Word<u32>> = [
            1u32, 2u32, 3u32, 1u32, 2u32, 3u32, 1u32, 2u32, 3u32, 1u32, 2u32, 3u32, 1u32, 2u32,
            3u32, 1u32,
        ]
        .iter()
        .map(|&vi| vi.into())
        .collect();

        let circuit = MsgScheduleCircuit::<u32>(PhantomData);

        let output = circuit.compute(&input);
        assert_eq!(output.len(), 64);

        let proof = Prover::<u32, ChaCha20Rng, Keccak256>::prove::<ThreadRng, SIGMA>(
            &mut rng, &input, &circuit, &output,
        )
        .unwrap();

        Verifier::<u32, ChaCha20Rng, Keccak256>::verify(&proof, &circuit, &output).unwrap();
    }
}
