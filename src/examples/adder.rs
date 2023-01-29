use std::{
    fmt::{Debug, Display},
    marker::PhantomData,
    ops::{BitAnd, BitXor},
};

use crate::{
    circuit::Circuit,
    error::Error,
    gadgets::add_mod::{add_mod_verify, mpc_add_mod},
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    party::Party,
};

pub struct AddModCircuit<T>
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
    _t: PhantomData<T>,
}

impl<T> AddModCircuit<T>
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
    fn add_mod_2_pow_t_bits(&self, x: T, y: T) -> T {
        let mut carry = T::zero();

        for i in 0..T::bytes_len() * 8 - 1 {
            // let a = get_bit(x ^ carry, i);
            // let b = get_bit(y ^ carry, i);
            let a = (x ^ carry).get_bit(i);
            let b = (y ^ carry).get_bit(i);

            // let ci = (a & b) ^ get_bit(carry, i);
            let ci = (a & b) ^ carry.get_bit(i);
            // carry = set_bit(carry, i + 1, ci);
            let ci = match ci.value {
                0 => false,
                1 => true,
                _ => panic!("Not bit"),
            };
            carry = carry.set_bit(i + 1, ci);
        }

        x ^ y ^ carry
    }
}

impl<T> Circuit<T> for AddModCircuit<T>
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
    fn compute(&self, input: &Vec<GF2Word<T>>) -> Vec<GF2Word<T>> {
        assert_eq!(input.len(), 2);
        let res = self.add_mod_2_pow_t_bits(input[0].value, input[1].value);
        vec![res.into()]
    }

    fn compute_23_decomposition(
        &self,
        p1: &mut Party<T>,
        p2: &mut Party<T>,
        p3: &mut Party<T>,
    ) -> (Vec<GF2Word<T>>, Vec<GF2Word<T>>, Vec<GF2Word<T>>) {
        assert_eq!(p1.view.input.len(), 2);
        assert_eq!(p2.view.input.len(), 2);
        assert_eq!(p3.view.input.len(), 2);

        let input_p1 = (p1.view.input[0], p1.view.input[1]);
        let input_p2 = (p2.view.input[0], p2.view.input[1]);
        let input_p3 = (p3.view.input[0], p3.view.input[1]);

        let (o1, o2, o3) = mpc_add_mod(input_p1, input_p2, input_p3, p1, p2, p3);
        (vec![o1], vec![o2], vec![o3])
    }

    fn simulate_two_parties(
        &self,
        p: &mut Party<T>,
        p_next: &mut Party<T>,
    ) -> Result<(Vec<GF2Word<T>>, Vec<GF2Word<T>>), Error> {
        assert_eq!(p.view.input.len(), 2);
        assert_eq!(p_next.view.input.len(), 2);

        let input_p = (p.view.input[0], p.view.input[1]);
        let input_p_next = (p_next.view.input[0], p_next.view.input[1]);

        let (o1, o2) = add_mod_verify(input_p, input_p_next, p, p_next);
        Ok((vec![o1], vec![o2]))
    }

    fn party_output_len(&self) -> usize {
        1
    }

    fn num_of_mul_gates(&self) -> usize {
        1
    }
}

#[cfg(test)]
mod test_adder {
    use std::marker::PhantomData;

    use rand::{rngs::ThreadRng, thread_rng};
    use rand_chacha::ChaCha20Rng;
    use sha3::Keccak256;

    use crate::{circuit::Circuit, gf2_word::GF2Word, prover::Prover, verifier::Verifier};

    use super::AddModCircuit;

    #[test]
    fn test_circuit() {
        let mut rng = thread_rng();
        let security_param = 80;
        let input: Vec<GF2Word<u32>> = [4294967295u32, 1].iter().map(|&vi| vi.into()).collect();

        let circuit = AddModCircuit::<u32> { _t: PhantomData };

        let output = circuit.compute(&input);

        let proof = Prover::<u32, ChaCha20Rng, Keccak256>::prove::<ThreadRng>(
            &mut rng,
            &input,
            &circuit,
            security_param,
            &output,
        )
        .unwrap();

        Verifier::<u32, ChaCha20Rng, Keccak256>::verify(&proof, &circuit, security_param, &output)
            .unwrap();
    }
}
