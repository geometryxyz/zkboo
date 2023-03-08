mod compression;
mod iv;
mod msg_schedule;

use std::ops::Deref;

/// TODO: Doc
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

// Working variables
struct A(u32);
impl Deref for A {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct B(u32);
impl Deref for B {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
struct C(u32);
impl Deref for C {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
struct D(u32);
impl Deref for D {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
struct E(u32);
impl Deref for E {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
struct F(u32);
impl Deref for F {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
struct G(u32);
impl Deref for G {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct H(u32);
impl Deref for H {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
