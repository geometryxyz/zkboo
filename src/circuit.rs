use crate::{
    error::Error,
    gf2_word::{GF2Word, Value},
    party::Party,
};

pub type Output<T> = Vec<GF2Word<T>>;
pub type TwoThreeDecOutput<T> = (Output<T>, Output<T>, Output<T>);

pub trait Circuit<T: Value>: Sync {
    fn compute(&self, input: &[u8]) -> Vec<GF2Word<T>>;

    /// Decompose this circuit into 3 branches such that the values computed in
    /// 2 branches reveals no information about the input x.
    fn compute_23_decomposition(
        &self,
        p1: &mut Party<T>,
        p2: &mut Party<T>,
        p3: &mut Party<T>,
    ) -> TwoThreeDecOutput<T>;
    fn simulate_two_parties(
        &self,
        p: &mut Party<T>,
        p_next: &mut Party<T>,
    ) -> Result<(Output<T>, Output<T>), Error>;
    fn party_input_len(&self) -> usize;
    fn party_output_len(&self) -> usize;
    fn num_of_mul_gates(&self) -> usize;
}

#[cfg(test)]
mod circuit_tests {
    use std::marker::PhantomData;

    use rand::{rngs::ThreadRng, thread_rng};
    use rand_chacha::ChaCha20Rng;
    use sha3::Keccak256;

    use super::{Circuit, Output, TwoThreeDecOutput};
    use crate::{
        error::Error,
        gadgets::{mpc_and, mpc_and_verify, mpc_xor, prepare::generic_parse},
        gf2_word::{GF2Word, Value},
        party::Party,
        prover::Prover,
        verifier::Verifier,
    };

    // computes: (x1 ^ x2) & (x3 ^ x4) & x5
    #[derive(Clone, Copy)]
    struct SimpleCircuit1<T>(PhantomData<T>);

    impl<T: Value> Circuit<T> for SimpleCircuit1<T> {
        fn compute(&self, input: &[u8]) -> Vec<GF2Word<T>> {
            let x = generic_parse(input, self.party_input_len());
            vec![(x[0] ^ x[1]) & (x[2] ^ x[3]) & x[4]]
        }

        fn compute_23_decomposition(
            &self,
            p1: &mut Party<T>,
            p2: &mut Party<T>,
            p3: &mut Party<T>,
        ) -> TwoThreeDecOutput<T> {
            // prepare
            let x = generic_parse(&p1.view.input, 5);
            let y = generic_parse(&p2.view.input, 5);
            let z = generic_parse(&p3.view.input, 5);

            let (x1, x2, x3, x4, x5) = (x[0], x[1], x[2], x[3], x[4]);
            let (y1, y2, y3, y4, y5) = (y[0], y[1], y[2], y[3], y[4]);
            let (z1, z2, z3, z4, z5) = (z[0], z[1], z[2], z[3], z[4]);

            let (a1, a2, a3) = mpc_xor((x1, x2), (y1, y2), (z1, z2));
            let (b1, b2, b3) = mpc_xor((x3, x4), (y3, y4), (z3, z4));

            let (ab1, ab2, ab3) = mpc_and((a1, b1), (a2, b2), (a3, b3), p1, p2, p3);

            let (o1, o2, o3) = mpc_and((ab1, x5), (ab2, y5), (ab3, z5), p1, p2, p3);

            (vec![o1], vec![o2], vec![o3])
        }

        fn simulate_two_parties(
            &self,
            p: &mut Party<T>,
            p_next: &mut Party<T>,
        ) -> Result<(Output<T>, Output<T>), Error> {
            let p_inputs = generic_parse(&p.view.input, self.party_input_len());
            let p_next_inputs = generic_parse(&p_next.view.input, self.party_input_len());

            let (x1, x2, x3, x4, x5) = (
                p_inputs[0],
                p_inputs[1],
                p_inputs[2],
                p_inputs[3],
                p_inputs[4],
            );

            let (y1, y2, y3, y4, y5) = (
                p_next_inputs[0],
                p_next_inputs[1],
                p_next_inputs[2],
                p_next_inputs[3],
                p_next_inputs[4],
            );

            let a1 = x1 ^ x2;
            let b1 = x3 ^ x4;

            let a2 = y1 ^ y2;
            let b2 = y3 ^ y4;

            let (ab1, ab2) = mpc_and_verify((a1, b1), (a2, b2), p, p_next)?;
            let (o1, o2) = mpc_and_verify((ab1, x5), (ab2, y5), p, p_next)?;

            Ok((vec![o1], vec![o2]))
        }

        fn party_input_len(&self) -> usize {
            5
        }

        fn party_output_len(&self) -> usize {
            1
        }

        fn num_of_mul_gates(&self) -> usize {
            2
        }
    }

    #[test]
    fn test_full_run() {
        let mut rng = thread_rng();
        const SIGMA: usize = 40;
        let input: Vec<u8> = [
            5u32.to_le_bytes(),
            4u32.to_le_bytes(),
            7u32.to_le_bytes(),
            2u32.to_le_bytes(),
            9u32.to_le_bytes(),
        ]
        .into_iter()
        .flatten()
        .collect();

        let circuit = SimpleCircuit1(PhantomData);
        let output = circuit.compute(&input);

        let proof = Prover::<u32, ChaCha20Rng, Keccak256>::prove::<ThreadRng, SIGMA>(
            &mut rng, &input, &circuit, &output,
        )
        .unwrap();

        Verifier::<u32, ChaCha20Rng, Keccak256>::verify(proof, &circuit, &output).unwrap();
    }
}
