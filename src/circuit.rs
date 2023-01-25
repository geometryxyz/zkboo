use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use crate::{
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    party::Party,
};

pub trait Circuit<T>
where
    T: Copy + Display + BitAnd<Output = T> + BitXor<Output = T> + BitUtils + BytesInfo + GenRand,
{
    fn compute(input: &Vec<GF2Word<T>>) -> GF2Word<T>;
    fn compute_23_decomposition(&self, p1: &mut Party<T>, p2: &mut Party<T>, p3: &mut Party<T>);
}

#[cfg(test)]
mod circuit_tests {
    use std::{
        fmt::Display,
        ops::{BitAnd, BitXor},
    };

    use rand::thread_rng;

    use super::Circuit;
    use crate::{
        gadgets::{mpc_and, mpc_xor},
        gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
        party::Party,
        prover::Prover,
    };

    // computes: (x1 ^ x2) & (x3 ^ x4) & x5
    struct SimpleCircuit1 {}

    impl<T> Circuit<T> for SimpleCircuit1
    where
        T: Copy
            + Display
            + BitAnd<Output = T>
            + BitXor<Output = T>
            + BitUtils
            + BytesInfo
            + GenRand,
    {
        fn compute(input: &Vec<GF2Word<T>>) -> GF2Word<T> {
            assert_eq!(input.len(), 5);

            (input[0] ^ input[1]) & (input[2] ^ input[3]) & input[4]
        }

        fn compute_23_decomposition(
            &self,
            p1: &mut Party<T>,
            p2: &mut Party<T>,
            p3: &mut Party<T>,
        ) {
            assert_eq!(p1.view.input.len(), 5);
            assert_eq!(p2.view.input.len(), 5);
            assert_eq!(p3.view.input.len(), 5);

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

            let (ab1, ab2, ab3) = mpc_and(
                (a1, b1),
                (a2, b2),
                (a3, b3),
                &mut p1.view,
                &mut p2.view,
                &mut p3.view,
            );

            let (o1, o2, o3) = mpc_and(
                (ab1, x5),
                (ab2, y5),
                (ab3, z5),
                &mut p1.view,
                &mut p2.view,
                &mut p3.view,
            );

            println!("output is: {}", o1.value ^ o2.value ^ o3.value);
        }
    }

    #[test]
    fn test_circuit1() {
        let mut rng = thread_rng();
        let input: Vec<GF2Word<_>> = [5u8, 4, 7, 2, 9].iter().map(|&vi| vi.into()).collect();

        let output = SimpleCircuit1::compute(&input);
        println!("{:?}", output);

        let circuit = SimpleCircuit1 {};
        Prover::prove(&mut rng, &input, &circuit);
    }
}