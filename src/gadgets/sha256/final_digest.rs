use crate::{
    gadgets::add_mod::{add_mod_verify, adder, mpc_add_mod},
    gf2_word::GF2Word,
    party::Party,
};

use super::{iv::init_iv, State};

pub fn digest(compression_output: &[GF2Word<u32>; 8]) -> Vec<GF2Word<u32>> {
    let hs = init_iv().to_vec();
    hs.into_iter()
        .zip(compression_output.iter())
        .map(|(hs, &output)| adder(hs.value, output.value).into())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

pub fn mpc_update_state(
    compression_output_p1: &[GF2Word<u32>; 8],
    compression_output_p2: &[GF2Word<u32>; 8],
    compression_output_p3: &[GF2Word<u32>; 8],
    state: &(State, State, State),
    p1: &mut Party<u32>,
    p2: &mut Party<u32>,
    p3: &mut Party<u32>,
) -> (State, State, State) {
    let mut output_1 = Vec::with_capacity(8);
    let mut output_2 = Vec::with_capacity(8);
    let mut output_3 = Vec::with_capacity(8);

    let hs_1 = state.0.to_vec();
    let hs_2 = state.1.to_vec();
    let hs_3 = state.2.to_vec();

    for i in 0..8 {
        let (o1, o2, o3) = mpc_add_mod(
            (compression_output_p1[i], hs_1[i]),
            (compression_output_p2[i], hs_2[i]),
            (compression_output_p3[i], hs_3[i]),
            p1,
            p2,
            p3,
        );

        output_1.push(o1);
        output_2.push(o2);
        output_3.push(o3);
    }

    (output_1.into(), output_2.into(), output_3.into())
}

pub fn mpc_update_state_verify(
    compression_output_p: &[GF2Word<u32>; 8],
    compression_output_p_next: &[GF2Word<u32>; 8],
    state: &(State, State),
    p: &mut Party<u32>,
    p_next: &mut Party<u32>,
) -> (State, State) {
    let hs_p = state.0.to_vec();
    let hs_p_next = state.1.to_vec();

    let mut output_p = Vec::with_capacity(8);
    let mut output_p_next = Vec::with_capacity(8);

    for i in 0..8 {
        let (o1, o2) = add_mod_verify(
            (compression_output_p[i], hs_p[i]),
            (compression_output_p_next[i], hs_p_next[i]),
            p,
            p_next,
        );

        output_p.push(o1);
        output_p_next.push(o2);
    }

    (output_p.into(), output_p_next.into())
}

#[cfg(test)]
mod test_digest {

    use rand::{rngs::ThreadRng, thread_rng};
    use rand_chacha::ChaCha20Rng;
    use sha3::Keccak256;

    use crate::{
        circuit::{Circuit, Output},
        error::Error,
        gadgets::prepare::generic_parse,
        gf2_word::GF2Word,
        party::Party,
        prover::Prover,
        verifier::Verifier,
    };

    use super::*;

    pub struct DigestCircuit;

    impl Circuit<u32> for DigestCircuit {
        fn compute(&self, input: &[u8]) -> Vec<GF2Word<u32>> {
            let input = generic_parse(input, self.party_input_len());
            digest(&input.try_into().unwrap())
        }

        fn compute_23_decomposition(
            &self,
            p1: &mut Party<u32>,
            p2: &mut Party<u32>,
            p3: &mut Party<u32>,
        ) -> (Vec<GF2Word<u32>>, Vec<GF2Word<u32>>, Vec<GF2Word<u32>>) {
            let p1_words = generic_parse(&p1.view.input, self.party_input_len());
            let p2_words = generic_parse(&p2.view.input, self.party_input_len());
            let p3_words = generic_parse(&p3.view.input, self.party_input_len());

            let state_1 = init_iv();
            let state_2 = init_iv();
            let state_3 = init_iv();

            let (o1, o2, o3) = mpc_update_state(
                &p1_words.try_into().unwrap(),
                &p2_words.try_into().unwrap(),
                &p3_words.try_into().unwrap(),
                &(
                    state_1.to_vec().into(),
                    state_2.to_vec().into(),
                    state_3.to_vec().into(),
                ),
                p1,
                p2,
                p3,
            );

            (o1.to_vec(), o2.to_vec(), o3.to_vec())
        }

        fn simulate_two_parties(
            &self,
            p: &mut Party<u32>,
            p_next: &mut Party<u32>,
        ) -> Result<(Output<u32>, Output<u32>), Error> {
            let p_words = generic_parse(&p.view.input, self.party_input_len());
            let p_next_words = generic_parse(&p_next.view.input, self.party_input_len());

            let state_p = init_iv();
            let state_p_next = init_iv();

            let (o1, o2) = mpc_update_state_verify(
                &p_words.try_into().unwrap(),
                &p_next_words.try_into().unwrap(),
                &(state_p.to_vec().into(), state_p_next.to_vec().into()),
                p,
                p_next,
            );

            Ok((o1.to_vec(), o2.to_vec()))
        }

        fn party_input_len(&self) -> usize {
            8
        }

        fn party_output_len(&self) -> usize {
            8
        }

        fn num_of_mul_gates(&self) -> usize {
            8
        }
    }

    #[test]
    fn test_circuit() {
        let mut rng = thread_rng();
        const SIGMA: usize = 80;
        let input: Vec<u8> = crate::gadgets::sha256::test_vectors::short::COMPRESSION_OUTPUT
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();

        let circuit = DigestCircuit;

        let output = circuit.compute(&input);
        let expected_output = crate::gadgets::sha256::test_vectors::short::DIGEST_OUTPUT;
        for (&word, &expected_word) in output.iter().zip(expected_output.iter()) {
            assert_eq!(word.value, expected_word);
        }

        let proof = Prover::<u32, ChaCha20Rng, Keccak256>::prove::<ThreadRng, SIGMA>(
            &mut rng, &input, &circuit, &output,
        )
        .unwrap();

        Verifier::<u32, ChaCha20Rng, Keccak256>::verify(proof, &circuit, &output).unwrap();
    }
}
