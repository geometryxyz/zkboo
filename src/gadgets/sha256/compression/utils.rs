use super::super::*;
use crate::gf2_word::BitUtils;

struct S0(u32);
impl std::ops::Deref for S0 {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct S1(u32);
impl std::ops::Deref for S1 {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
fn sigma_0(a: A) -> S0 {
    S0(a.right_rotate(2) ^ a.right_rotate(13) ^ a.right_rotate(22))
}

/// S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
fn sigma_1(e: E) -> S1 {
    S1(e.right_rotate(6) ^ e.right_rotate(11) ^ e.right_rotate(25))
}
