use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use crate::{
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    party::Party,
};

// fn adder2(x: u8, y: u8) -> u8 {
//     let mut carry: u8 = 0;

//     for i in 0u8..7 {
//         let a = get_bit(x ^ carry, i);
//         let b = get_bit(y ^ carry, i);

//         let ci = (a & b) ^ get_bit(carry, i);
//         carry = set_bit(carry, i + 1, ci);
//     }

//     x ^ y ^ carry
// }

fn bit_and(
    input_p1: (GF2Word<u8>, GF2Word<u8>),
    input_p2: (GF2Word<u8>, GF2Word<u8>),
    r_p1: GF2Word<u8>,
    r_p2: GF2Word<u8>,
) -> GF2Word<u8> {
    (input_p1.0 & input_p1.1)
        ^ (input_p1.0 & input_p2.1)
        ^ (input_p1.1 & input_p2.0)
        ^ (r_p1 ^ r_p2)
}

/// Performs addition modulo 2^(T::bits_size)
/// Works bit by bit and appends full carry in view, that's why it's counted as just one gate
pub fn mpc_add_mod<T>(
    input_p1: (GF2Word<T>, GF2Word<T>),
    input_p2: (GF2Word<T>, GF2Word<T>),
    input_p3: (GF2Word<T>, GF2Word<T>),
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
    let rand_p1 = p1.read_tape();
    let rand_p2 = p2.read_tape();
    let rand_p3 = p3.read_tape();

    let mut carry_p1: GF2Word<T> = T::zero().into();
    let mut carry_p2: GF2Word<T> = T::zero().into();
    let mut carry_p3: GF2Word<T> = T::zero().into();

    let get_bit = |ci: GF2Word<u8>| -> bool {
        match ci.value {
            0 => false,
            1 => true,
            _ => panic!("Not bit"),
        }
    };

    for i in 0..T::bytes_len() * 8 - 1 {
        let ri_p1 = rand_p1.value.get_bit(i);
        let ri_p2 = rand_p2.value.get_bit(i);
        let ri_p3 = rand_p3.value.get_bit(i);

        let a_p1 = (input_p1.0.value ^ carry_p1.value).get_bit(i);
        let b_p1 = (input_p1.1.value ^ carry_p1.value).get_bit(i);

        let a_p2 = (input_p2.0.value ^ carry_p2.value).get_bit(i);
        let b_p2 = (input_p2.1.value ^ carry_p2.value).get_bit(i);

        let a_p3 = (input_p3.0.value ^ carry_p3.value).get_bit(i);
        let b_p3 = (input_p3.1.value ^ carry_p3.value).get_bit(i);

        let ci_p1 = bit_and((a_p1, b_p1), (a_p2, b_p2), ri_p1, ri_p2) ^ carry_p1.value.get_bit(i);
        let ci_p2 = bit_and((a_p2, b_p2), (a_p3, b_p3), ri_p2, ri_p3) ^ carry_p2.value.get_bit(i);
        let ci_p3 = bit_and((a_p3, b_p3), (a_p1, b_p1), ri_p3, ri_p1) ^ carry_p3.value.get_bit(i);

        carry_p1 = carry_p1.value.set_bit(i + 1, get_bit(ci_p1)).into();
        carry_p2 = carry_p2.value.set_bit(i + 1, get_bit(ci_p2)).into();
        carry_p3 = carry_p3.value.set_bit(i + 1, get_bit(ci_p3)).into();
    }

    p1.view.send_msg(carry_p1);
    p2.view.send_msg(carry_p2);
    p3.view.send_msg(carry_p3);

    let o1 = input_p1.0 ^ input_p1.1 ^ carry_p1;
    let o2 = input_p2.0 ^ input_p2.1 ^ carry_p2;
    let o3 = input_p3.0 ^ input_p3.1 ^ carry_p3;

    (o1, o2, o3)
}

pub fn add_mod_verify<T>(
    input_p: (GF2Word<T>, GF2Word<T>),
    input_p_next: (GF2Word<T>, GF2Word<T>),
    p: &mut Party<T>,
    p_next: &mut Party<T>,
) -> (GF2Word<T>, GF2Word<T>)
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
    let ri = p.read_tape();
    let ri_next = p_next.read_tape();

    let mut carry_p = T::zero().into();
    let carry_p_next = p_next.view.read_next();

    let get_bit = |ci: GF2Word<u8>| -> bool {
        match ci.value {
            0 => false,
            1 => true,
            _ => panic!("Not bit"),
        }
    };

    for i in 0..T::bytes_len() * 8 - 1 {
        let ri_p = ri.value.get_bit(i);
        let ri_p_next = ri_next.value.get_bit(i);

        let a_p = (input_p.0 ^ carry_p).value.get_bit(i);
        let b_p = (input_p.1 ^ carry_p).value.get_bit(i);

        let a_p_next = (input_p_next.0 ^ carry_p_next).value.get_bit(i);
        let b_p_next = (input_p_next.1 ^ carry_p_next).value.get_bit(i);

        let ci_p =
            bit_and((a_p, b_p), (a_p_next, b_p_next), ri_p, ri_p_next) ^ carry_p.value.get_bit(i);

        carry_p = carry_p.value.set_bit(i + 1, get_bit(ci_p)).into();
    }

    p.view.send_msg(carry_p);

    let o1 = input_p.0 ^ input_p.1 ^ carry_p;
    let o2 = input_p_next.0 ^ input_p_next.1 ^ carry_p_next;

    (o1, o2)
}
