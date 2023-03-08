mod ch;
mod maj;
mod utils;

use super::*;
use crate::{
    gadgets::Party,
    gf2_word::{BitUtils, GF2Word},
};

/// temp1 := h + S1 + ch + k[i] + w[i]
fn temp1(
    h: (GF2Word<u32>, GF2Word<u32>, GF2Word<u32>),
    s1: (GF2Word<u32>, GF2Word<u32>, GF2Word<u32>),
    ch: (GF2Word<u32>, GF2Word<u32>, GF2Word<u32>),
    k_i: GF2Word<u32>,
    w_i: GF2Word<u32>,
) -> GF2Word<u32> {
    todo!()
}

/// temp2 := S0 + maj
fn temp2() {
    todo!()
}

fn mpc_compression(
    init: WorkingVariables,
    input_p1: [GF2Word<u32>; 64],
    input_p2: [GF2Word<u32>; 64],
    input_p3: [GF2Word<u32>; 64],
    p1: &mut Party<u32>,
    p2: &mut Party<u32>,
    p3: &mut Party<u32>,
) -> [u32; 8] {
    let mut variables = init;

    for i in 0..64 {
        variables.h = H(*variables.g);
        // h := g
        // g := f
        // f := e
        // e := d + temp1
        // d := c
        // c := b
        // b := a
        // a := temp1 + temp2
    }
    todo!()
}
