mod compression;
mod final_digest;
mod iv;
mod msg_schedule;
mod test_vectors;

use crate::gf2_word::GF2Word;
use std::ops::Deref;

/// TODO: Doc
#[derive(Debug)]
pub struct WorkingVariables {
    a: A,
    b: B,
    c: C,
    d: D,
    e: E,
    f: F,
    g: G,
    h: H,
}

impl WorkingVariables {
    pub fn to_vec(&self) -> Vec<GF2Word<u32>> {
        [
            (*self.a).into(),
            (*self.b).into(),
            (*self.c).into(),
            (*self.d).into(),
            (*self.e).into(),
            (*self.f).into(),
            (*self.g).into(),
            (*self.h).into(),
        ]
        .to_vec()
    }
}

// Working variables
#[derive(Debug, Clone, Copy)]
pub struct A(GF2Word<u32>);
impl Deref for A {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct B(GF2Word<u32>);
impl Deref for B {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[derive(Debug, Clone, Copy)]
pub struct C(GF2Word<u32>);
impl Deref for C {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[derive(Debug, Clone, Copy)]
pub struct D(GF2Word<u32>);
impl Deref for D {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[derive(Debug, Clone, Copy)]
pub struct E(GF2Word<u32>);
impl Deref for E {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[derive(Debug, Clone, Copy)]
pub struct F(GF2Word<u32>);
impl Deref for F {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[derive(Debug, Clone, Copy)]
pub struct G(GF2Word<u32>);
impl Deref for G {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct H(GF2Word<u32>);
impl Deref for H {
    type Target = GF2Word<u32>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
