use std::{
    fmt::Display,
    ops::{BitAnd, BitXor},
};

use crate::{
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    view::View,
};

pub fn mpc_xor<T>(
    input_p1: (GF2Word<T>, GF2Word<T>),
    input_p2: (GF2Word<T>, GF2Word<T>),
    input_p3: (GF2Word<T>, GF2Word<T>),
) -> (GF2Word<T>, GF2Word<T>, GF2Word<T>)
where
    T: Copy + Display + BitAnd<Output = T> + BitXor<Output = T> + BitUtils + BytesInfo + GenRand,
{
    let output_p1 = input_p1.0 ^ input_p1.1;
    let output_p2 = input_p2.0 ^ input_p2.1;
    let output_p3 = input_p3.0 ^ input_p3.1;

    (output_p1, output_p2, output_p3)
}

// TODO: add randomness
pub fn mpc_and<T>(
    input_p1: (GF2Word<T>, GF2Word<T>),
    input_p2: (GF2Word<T>, GF2Word<T>),
    input_p3: (GF2Word<T>, GF2Word<T>),
    view_p1: &mut View<T>,
    view_p2: &mut View<T>,
    view_p3: &mut View<T>,
) -> (GF2Word<T>, GF2Word<T>, GF2Word<T>)
where
    T: Copy + Display + BitAnd<Output = T> + BitXor<Output = T> + BitUtils + BytesInfo + GenRand,
{
    let output_p1 =
        (input_p1.0 & input_p1.1) ^ (input_p1.0 & input_p2.1) ^ (input_p1.1 & input_p2.0);
    let output_p2 =
        (input_p2.0 & input_p2.1) ^ (input_p2.0 & input_p3.1) ^ (input_p2.1 & input_p3.0);
    let output_p3 =
        (input_p3.0 & input_p3.1) ^ (input_p3.0 & input_p1.1) ^ (input_p3.1 & input_p1.0);

    view_p1.send_msg(output_p1);
    view_p2.send_msg(output_p2);
    view_p3.send_msg(output_p3);

    (output_p1, output_p2, output_p3)
}
