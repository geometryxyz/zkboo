pub mod add_mod;
pub mod verifier;

use std::{
    fmt::{Debug, Display},
    ops::{BitAnd, BitXor},
};

use crate::{
    error::Error,
    gf2_word::{BitUtils, BytesInfo, GF2Word, GenRand},
    party::Party,
};

pub fn mpc_xor<T>(
    input_p1: (GF2Word<T>, GF2Word<T>),
    input_p2: (GF2Word<T>, GF2Word<T>),
    input_p3: (GF2Word<T>, GF2Word<T>),
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
    let output_p1 = input_p1.0 ^ input_p1.1;
    let output_p2 = input_p2.0 ^ input_p2.1;
    let output_p3 = input_p3.0 ^ input_p3.1;

    (output_p1, output_p2, output_p3)
}

pub fn mpc_and<T>(
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
    let r1 = p1.read_tape();
    let r2 = p2.read_tape();
    let r3 = p3.read_tape();

    let output_p1 = (input_p1.0 & input_p1.1)
        ^ (input_p1.0 & input_p2.1)
        ^ (input_p1.1 & input_p2.0)
        ^ (r1 ^ r2);
    let output_p2 = (input_p2.0 & input_p2.1)
        ^ (input_p2.0 & input_p3.1)
        ^ (input_p2.1 & input_p3.0)
        ^ (r2 ^ r3);
    let output_p3 = (input_p3.0 & input_p3.1)
        ^ (input_p3.0 & input_p1.1)
        ^ (input_p3.1 & input_p1.0)
        ^ (r3 ^ r1);

    p1.view.send_msg(output_p1);
    p2.view.send_msg(output_p2);
    p3.view.send_msg(output_p3);

    (output_p1, output_p2, output_p3)
}

pub fn and_verify<T>(
    input_p: (GF2Word<T>, GF2Word<T>),
    input_p_next: (GF2Word<T>, GF2Word<T>),
    p: &mut Party<T>,
    p_next: &mut Party<T>,
) -> Result<(GF2Word<T>, GF2Word<T>), Error>
where
    T: Copy
        + Default
        + Display
        + Debug
        + BitAnd<Output = T>
        + BitXor<Output = T>
        + BitUtils
        + BytesInfo
        + GenRand
        + PartialEq,
{
    let ri = p.read_tape();
    let ri_next = p_next.read_tape();

    let output_p = (input_p.0 & input_p.1)
        ^ (input_p.0 & input_p_next.1)
        ^ (input_p.1 & input_p_next.0)
        ^ (ri ^ ri_next);

    /*
       Do not check view consistency, instead generated view will be checked when checking fiat shamir
       as noted in O6 of (https://eprint.iacr.org/2017/279.pdf)
    */
    p.view.send_msg(output_p);

    Ok((output_p, p_next.read_view()))
}
