use crate::{
    error::Error,
    gadgets::add_mod::{add_mod_verify, add_mod_verify_k, adder, mpc_add_mod, mpc_add_mod_k},
    gf2_word::GF2Word,
    party::Party,
};

pub fn temp1(h: u32, s1: u32, ch: u32, w_i: u32, k_i: u32) -> u32 {
    let var_1 = adder(h, s1);
    let var_2 = adder(var_1, ch);
    let var_3 = adder(var_2, k_i);
    adder(var_3, w_i)
}

/// temp1 := h + S1 + ch + k[i] + w[i]
pub fn mpc_temp1(
    (h_1, s1_1, ch_1, wi_1): (GF2Word<u32>, GF2Word<u32>, GF2Word<u32>, GF2Word<u32>),
    (h_2, s1_2, ch_2, wi_2): (GF2Word<u32>, GF2Word<u32>, GF2Word<u32>, GF2Word<u32>),
    (h_3, s1_3, ch_3, wi_3): (GF2Word<u32>, GF2Word<u32>, GF2Word<u32>, GF2Word<u32>),
    k_i: GF2Word<u32>,
    p1: &mut Party<u32>,
    p2: &mut Party<u32>,
    p3: &mut Party<u32>,
) -> (GF2Word<u32>, GF2Word<u32>, GF2Word<u32>) {
    // first_var = h + S1
    let (first_var_1, first_var_2, first_var_3) =
        mpc_add_mod((h_1, s1_1), (h_2, s1_2), (h_3, s1_3), p1, p2, p3);

    // second_var = first_var + ch
    let (second_var_1, second_var_2, second_var_3) = mpc_add_mod(
        (first_var_1, ch_1),
        (first_var_2, ch_2),
        (first_var_3, ch_3),
        p1,
        p2,
        p3,
    );

    // third_var = second_var + wi
    let (third_var_1, third_var_2, third_var_3) = mpc_add_mod(
        (second_var_1, wi_1),
        (second_var_2, wi_2),
        (second_var_3, wi_3),
        p1,
        p2,
        p3,
    );

    // output = third_var + ki
    mpc_add_mod_k(third_var_1, third_var_2, third_var_3, k_i, p1, p2, p3)
}

pub fn mpc_temp1_verify(
    (h_p, s1_p, ch_p, wi_p): (GF2Word<u32>, GF2Word<u32>, GF2Word<u32>, GF2Word<u32>),
    (h_p_next, s1_p_next, ch_p_next, wi_p_next): (
        GF2Word<u32>,
        GF2Word<u32>,
        GF2Word<u32>,
        GF2Word<u32>,
    ),
    k_i: GF2Word<u32>,
    p: &mut Party<u32>,
    p_next: &mut Party<u32>,
) -> Result<(GF2Word<u32>, GF2Word<u32>), Error> {
    // first_var = h + S1
    let (first_var_p, first_var_p_next) =
        add_mod_verify((h_p, s1_p), (h_p_next, s1_p_next), p, p_next);

    // second_var = first_var + ch
    let (second_var_p, second_var_p_next) = add_mod_verify(
        (first_var_p, ch_p),
        (first_var_p_next, ch_p_next),
        p,
        p_next,
    );

    // third_var = second_var + wi
    let (third_var_p, third_var_p_next) = add_mod_verify(
        (second_var_p, wi_p),
        (second_var_p_next, wi_p_next),
        p,
        p_next,
    );

    // output = third_var + ki
    let (output_p, output_p_next) = add_mod_verify_k(third_var_p, third_var_p_next, k_i, p, p_next);

    Ok((output_p, output_p_next))
}

#[cfg(test)]
mod test_temp1 {
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

    pub struct Temp1Circuit {
        k: GF2Word<u32>,
    }

    impl Circuit<u32> for Temp1Circuit {
        fn compute(&self, input: &[GF2Word<u32>]) -> Vec<GF2Word<u32>> {
            assert_eq!(input.len(), 4);
            let res = temp1(
                input[0].value,
                input[1].value,
                input[2].value,
                input[3].value,
                self.k.value,
            );
            vec![res.into()]
        }

        fn compute_23_decomposition(
            &self,
            p1: &mut Party<u32>,
            p2: &mut Party<u32>,
            p3: &mut Party<u32>,
        ) -> (Vec<GF2Word<u32>>, Vec<GF2Word<u32>>, Vec<GF2Word<u32>>) {
            assert_eq!(p1.view.input.len(), 4);
            assert_eq!(p2.view.input.len(), 4);
            assert_eq!(p3.view.input.len(), 4);

            let input_p1 = (
                p1.view.input[0],
                p1.view.input[1],
                p1.view.input[2],
                p1.view.input[3],
            );
            let input_p2 = (
                p2.view.input[0],
                p2.view.input[1],
                p2.view.input[2],
                p2.view.input[3],
            );
            let input_p3 = (
                p3.view.input[0],
                p3.view.input[1],
                p3.view.input[2],
                p3.view.input[3],
            );

            let (o1, o2, o3) = mpc_temp1(input_p1, input_p2, input_p3, self.k, p1, p2, p3);
            (vec![o1], vec![o2], vec![o3])
        }

        fn simulate_two_parties(
            &self,
            p: &mut Party<u32>,
            p_next: &mut Party<u32>,
        ) -> Result<(Output<u32>, Output<u32>), Error> {
            assert_eq!(p.view.input.len(), 4);
            assert_eq!(p_next.view.input.len(), 4);

            let input_p = (
                p.view.input[0],
                p.view.input[1],
                p.view.input[2],
                p.view.input[3],
            );
            let input_p_next = (
                p_next.view.input[0],
                p_next.view.input[1],
                p_next.view.input[2],
                p_next.view.input[3],
            );

            let (o1, o2) = mpc_temp1_verify(input_p, input_p_next, self.k, p, p_next)?;

            Ok((vec![o1], vec![o2]))
        }

        fn party_output_len(&self) -> usize {
            1
        }

        fn num_of_mul_gates(&self) -> usize {
            4
        }
    }

    #[test]
    fn test_circuit() {
        let mut rng = thread_rng();
        const SIGMA: usize = 80;
        let input: Vec<GF2Word<u32>> = [381321u32, 32131u32, 328131u32, 313123]
            .iter()
            .map(|&vi| vi.into())
            .collect();

        let circuit = Temp1Circuit {
            k: 131321u32.into(),
        };

        let output = circuit.compute(&input);

        let proof = Prover::<u32, ChaCha20Rng, Keccak256>::prove::<ThreadRng, SIGMA>(
            &mut rng, &input, &circuit, &output,
        )
        .unwrap();

        Verifier::<u32, ChaCha20Rng, Keccak256>::verify(&proof, &circuit, &output).unwrap();
    }
}