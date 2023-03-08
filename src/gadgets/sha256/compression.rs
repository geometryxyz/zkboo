mod ch;
mod maj;
mod temp1;
mod temp2;

use self::{
    ch::{ch_verify, mpc_ch},
    maj::{maj, maj_verify, mpc_maj},
    temp1::{mpc_temp1, mpc_temp1_verify},
    temp2::{mpc_temp2, mpc_temp2_verify},
};

use super::{
    iv::{init_iv, k},
    *,
};
use crate::{
    error::Error,
    gadgets::{
        add_mod::{add_mod_verify, adder, mpc_add_mod},
        Party,
    },
    gf2_word::{BitUtils, GF2Word},
};

/// S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
pub fn sigma_0(a: A) -> GF2Word<u32> {
    let s0 = a.value.right_rotate(2) ^ a.value.right_rotate(13) ^ a.value.right_rotate(22);
    s0.into()
}

/// S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
pub fn sigma_1(e: E) -> GF2Word<u32> {
    let s1 = e.value.right_rotate(6) ^ e.value.right_rotate(11) ^ e.value.right_rotate(25);
    s1.into()
}

pub fn compression(w: &[GF2Word<u32>; 64]) -> Vec<GF2Word<u32>> {
    let mut variables = init_iv();

    for i in 0..64 {
        // - ch  := (e and f) xor ((not e) and g)
        let ch = ch::ch(
            variables.e.value,
            variables.f.value,
            variables.g.value,
        );
        // - S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
        let s1 = sigma_1(variables.e);
        // - temp1 := h + S1 + ch + k[i] + w[i]
        let temp_1 = temp1::temp1(variables.h.value, s1.value, ch, w[i].value, k[i]);
        // - S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
        let s0 = sigma_0(variables.a);
        // - maj := (a and b) xor (a and c) xor (b and c)
        let maj = maj(
            variables.a.value,
            variables.b.value,
            variables.c.value,
        );
        // - temp2 := S0 + maj
        let temp_2 = temp2::temp2(s0.value, maj);

        // h := g
        variables.h = H(*variables.g);
        // g := f
        variables.g = G(*variables.f);
        // f := e
        variables.f = F(*variables.e);
        // e := d + temp1
        variables.e = {
            let o = adder(variables.d.value, temp_1);
            E(o.into())
        };
        // d := c
        variables.d = D(*variables.c);
        // c := b
        variables.c = C(*variables.b);
        // b := a
        variables.b = B(*variables.a);
        // a := temp1 + temp2
        variables.a = {
            let o = adder(temp_1, temp_2);
            A(o.into())
        }
    }

    variables.to_vec()
}

pub fn mpc_compression(
    w_p1: &[GF2Word<u32>; 64],
    w_p2: &[GF2Word<u32>; 64],
    w_p3: &[GF2Word<u32>; 64],
    p1: &mut Party<u32>,
    p2: &mut Party<u32>,
    p3: &mut Party<u32>,
) -> (Vec<GF2Word<u32>>, Vec<GF2Word<u32>>, Vec<GF2Word<u32>>) {
    let mut variables_1 = init_iv();
    let mut variables_2 = init_iv();
    let mut variables_3 = init_iv();

    for i in 0..64 {
        // - S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
        let (s1_1, s1_2, s1_3) = (
            sigma_1(variables_1.e),
            sigma_1(variables_2.e),
            sigma_1(variables_3.e),
        );
        // - ch  := (e and f) xor ((not e) and g)
        let (ch_1, ch_2, ch_3) = {
            let input_p1 = (*variables_1.e, *variables_1.f, *variables_1.g);
            let input_p2 = (*variables_2.e, *variables_2.f, *variables_2.g);
            let input_p3 = (*variables_3.e, *variables_3.f, *variables_3.g);
            mpc_ch(input_p1, input_p2, input_p3, p1, p2, p3)
        };
        // - temp1 := h + S1 + ch + k[i] + w[i]
        let (temp1_1, temp1_2, temp1_3) = {
            let input_p1 = (*variables_1.h, s1_1, ch_1, w_p1[i]);
            let input_p2 = (*variables_2.h, s1_2, ch_2, w_p2[i]);
            let input_p3 = (*variables_3.h, s1_3, ch_3, w_p3[i]);

            mpc_temp1(input_p1, input_p2, input_p3, k[i].into(), p1, p2, p3)
        };
        // - S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
        let (s0_1, s0_2, s0_3) = (
            sigma_0(variables_1.a),
            sigma_0(variables_2.a),
            sigma_0(variables_3.a),
        );
        let (maj_1, maj_2, maj_3) = {
            let input_p1 = (*variables_1.a, *variables_1.b, *variables_1.c);
            let input_p2 = (*variables_2.a, *variables_2.b, *variables_2.c);
            let input_p3 = (*variables_3.a, *variables_3.b, *variables_3.c);

            mpc_maj(input_p1, input_p2, input_p3, p1, p2, p3)
        };
        let (temp2_1, temp2_2, temp2_3) = {
            let input_p1 = (s0_1, maj_1);
            let input_p2 = (s0_2, maj_2);
            let input_p3 = (s0_3, maj_3);

            mpc_temp2(input_p1, input_p2, input_p3, p1, p2, p3)
        };

        // h := g
        {
            variables_1.h = H(*variables_1.g);
            variables_2.h = H(*variables_2.g);
            variables_3.h = H(*variables_3.g);
        }
        // g := f
        {
            variables_1.g = G(*variables_1.f);
            variables_2.g = G(*variables_2.f);
            variables_3.g = G(*variables_3.f);
        }
        // f := e
        {
            variables_1.f = F(*variables_1.e);
            variables_2.f = F(*variables_2.e);
            variables_3.f = F(*variables_3.e);
        }
        // e := d + temp1
        (variables_1.e, variables_2.e, variables_3.e) = {
            let input_p1 = (*variables_1.d, temp1_1);
            let input_p2 = (*variables_2.d, temp1_2);
            let input_p3 = (*variables_3.d, temp1_3);

            let (o1, o2, o3) = mpc_add_mod(input_p1, input_p2, input_p3, p1, p2, p3);
            (E(o1), E(o2), E(o3))
        };
        // d := c
        {
            variables_1.d = D(*variables_1.c);
            variables_2.d = D(*variables_2.c);
            variables_3.d = D(*variables_3.c);
        }
        // c := b
        {
            variables_1.c = C(*variables_1.b);
            variables_2.c = C(*variables_2.b);
            variables_3.c = C(*variables_3.b);
        }
        // b := a
        {
            variables_1.b = B(*variables_1.a);
            variables_2.b = B(*variables_2.a);
            variables_3.b = B(*variables_3.a);
        }
        // a := temp1 + temp2
        // temp2 := S0 + maj
        // Maj := (a and b) xor (a and c) xor (b and c)
        (variables_1.a, variables_2.a, variables_3.a) = {
            let input_p1 = (temp1_1, temp2_1);
            let input_p2 = (temp1_2, temp2_2);
            let input_p3 = (temp1_3, temp2_3);

            let (o1, o2, o3) = mpc_add_mod(input_p1, input_p2, input_p3, p1, p2, p3);
            (A(o1), A(o2), A(o3))
        };
    }
    (
        variables_1.to_vec(),
        variables_2.to_vec(),
        variables_3.to_vec(),
    )
}

pub fn mpc_compression_verify(
    w_p: &[GF2Word<u32>; 64],
    w_p_next: &[GF2Word<u32>; 64],
    p: &mut Party<u32>,
    p_next: &mut Party<u32>,
) -> Result<(Vec<GF2Word<u32>>, Vec<GF2Word<u32>>), Error> {
    let mut variables_p = init_iv();
    let mut variables_p_next = init_iv();

    for i in 0..64 {
        // - ch  := (e and f) xor ((not e) and g)
        let (ch_p, ch_p_next) = {
            let input_p = (*variables_p.e, *variables_p.f, *variables_p.g);
            let input_p_next = (
                *variables_p_next.e,
                *variables_p_next.f,
                *variables_p_next.g,
            );
            ch_verify(input_p, input_p_next, p, p_next)?
        };
        // - S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
        let (s1_p, s1_p_next) = (sigma_1(variables_p.e), sigma_1(variables_p_next.e));
        // - temp1 := h + S1 + ch + k[i] + w[i]
        let (temp1_p, temp1_p_next) = {
            let input_p = (*variables_p.h, s1_p, ch_p, w_p[i]);
            let input_p_next = (*variables_p_next.h, s1_p_next, ch_p_next, w_p_next[i]);

            mpc_temp1_verify(input_p, input_p_next, k[i].into(), p, p_next)?
        };
        // Maj := (a and b) xor (a and c) xor (b and c)
        let (maj_p, maj_p_next) = {
            let input_p = (*variables_p.a, *variables_p.b, *variables_p.c);
            let input_p_next = (
                *variables_p_next.a,
                *variables_p_next.b,
                *variables_p_next.c,
            );

            maj_verify(input_p, input_p_next, p, p_next)?
        };
        // - S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
        let (s0_p, s0_p_next) = (sigma_0(variables_p.a), sigma_0(variables_p_next.a));
        // temp2 := S0 + maj
        let (temp2_p, temp2_p_next) = {
            let input_p = (s0_p, maj_p);
            let input_p_next = (s0_p_next, maj_p_next);

            mpc_temp2_verify(input_p, input_p_next, p, p_next)?
        };

        // h := g
        {
            variables_p.h = H(*variables_p.g);
            variables_p_next.h = H(*variables_p_next.g);
        }
        // g := f
        {
            variables_p.g = G(*variables_p.f);
            variables_p_next.g = G(*variables_p_next.f);
        }
        // f := e
        {
            variables_p.f = F(*variables_p.e);
            variables_p_next.f = F(*variables_p_next.e);
        }
        // e := d + temp1
        (variables_p.e, variables_p_next.e) = {
            let input_p = (*variables_p.d, temp1_p);
            let input_p_next = (*variables_p_next.d, temp1_p_next);

            let (o1, o2) = add_mod_verify(input_p, input_p_next, p, p_next);
            (E(o1), E(o2))
        };
        // d := c
        {
            variables_p.d = D(*variables_p.c);
            variables_p_next.d = D(*variables_p_next.c);
        }
        // c := b
        {
            variables_p.c = C(*variables_p.b);
            variables_p_next.c = C(*variables_p_next.b);
        }
        // b := a
        {
            variables_p.b = B(*variables_p.a);
            variables_p_next.b = B(*variables_p_next.a);
        }
        // a := temp1 + temp2

        (variables_p.a, variables_p_next.a) = {
            let input_p = (temp1_p, temp2_p);
            let input_p_next = (temp1_p_next, temp2_p_next);

            let (o1, o2) = add_mod_verify(input_p, input_p_next, p, p_next);
            (A(o1), A(o2))
        }
    }
    Ok((variables_p.to_vec(), variables_p_next.to_vec()))
}

#[cfg(test)]
mod test_compression {
    

    use rand::{rngs::ThreadRng, thread_rng};
    use rand_chacha::ChaCha20Rng;
    use sha3::Keccak256;

    use crate::{
        circuit::{Circuit, Output},
        error::Error,
        gf2_word::{GF2Word},
        party::Party,
        prover::Prover,
        verifier::Verifier,
    };

    use super::*;

    pub struct CompressionCircuit;

    impl Circuit<u32> for CompressionCircuit {
        fn compute(&self, input: &[GF2Word<u32>]) -> Vec<GF2Word<u32>> {
            assert_eq!(input.len(), 64);
            compression(&input.try_into().unwrap())
        }

        fn compute_23_decomposition(
            &self,
            p1: &mut Party<u32>,
            p2: &mut Party<u32>,
            p3: &mut Party<u32>,
        ) -> (Vec<GF2Word<u32>>, Vec<GF2Word<u32>>, Vec<GF2Word<u32>>) {
            assert_eq!(p1.view.input.len(), 64);
            assert_eq!(p2.view.input.len(), 64);
            assert_eq!(p3.view.input.len(), 64);

            mpc_compression(
                &p1.view.input.clone().try_into().unwrap(),
                &p2.view.input.clone().try_into().unwrap(),
                &p3.view.input.clone().try_into().unwrap(),
                p1,
                p2,
                p3,
            )
        }

        fn simulate_two_parties(
            &self,
            p: &mut Party<u32>,
            p_next: &mut Party<u32>,
        ) -> Result<(Output<u32>, Output<u32>), Error> {
            assert_eq!(p.view.input.len(), 64);
            assert_eq!(p_next.view.input.len(), 64);

            let (o1, o2) = mpc_compression_verify(
                &p.view.input.clone().try_into().unwrap(),
                &p_next.view.input.clone().try_into().unwrap(),
                p,
                p_next,
            )?;

            Ok((o1.to_vec(), o2.to_vec()))
        }

        fn party_output_len(&self) -> usize {
            8
        }

        fn num_of_mul_gates(&self) -> usize {
            9 * 64
        }
    }

    #[test]
    fn test_circuit() {
        let mut rng = thread_rng();
        const SIGMA: usize = 80;
        let input: Vec<GF2Word<u32>> =
            crate::gadgets::sha256::test_vectors::MSG_SCHEDULE_TEST_OUTPUT
                .iter()
                .map(|&vi| vi.into())
                .collect();

        let circuit = CompressionCircuit;

        let output = circuit.compute(&input);
        let expected_output = crate::gadgets::sha256::test_vectors::COMPRESSION_OUTPUT;
        for (&word, &expected_word) in output.iter().zip(expected_output.iter()) {
            assert_eq!(word.value, expected_word);
        }

        let proof = Prover::<u32, ChaCha20Rng, Keccak256>::prove::<ThreadRng, SIGMA>(
            &mut rng, &input, &circuit, &output,
        )
        .unwrap();

        Verifier::<u32, ChaCha20Rng, Keccak256>::verify(&proof, &circuit, &output).unwrap();
    }
}
