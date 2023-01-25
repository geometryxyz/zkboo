use std::marker::PhantomData;
use sha3::{digest::OutputSizeUser, Digest};

pub struct SigmaProtocolStatelessFiatShamir<D: Clone + Digest> {
    _d: PhantomData<D>,
}

impl<D: Clone + Digest> SigmaProtocolStatelessFiatShamir<D> {
    pub fn sample_trits(
        seed: &[u8],
        public_data: &[u8],
        prover_msg: &[u8],
        r: usize,
    ) -> Vec<u8> {
        let with_prefix = |prefix: u8| {
            let mut hasher = D::new_with_prefix(&[prefix]);
            hasher.update(seed);
            hasher.update(public_data);
            hasher.update(prover_msg);

            hasher.finalize()
        };

        // local closure for which pos always < 8
        let get_bit = |x: u8, pos: usize| -> u8 { (x >> pos) & 1 };

        let mut trits = vec![0u8; r];

        let mut sampled: usize = 0;
        let mut prefix: u8 = 0;
        let mut pos = 0;

        let mut hash = with_prefix(prefix);

        while sampled < r {
            if pos >= <D as OutputSizeUser>::output_size() * 8 {
                prefix += 1;
                hash = with_prefix(prefix);
                pos = 0;
            }

            let b1 = get_bit(hash[(pos / 8)], pos % 8);
            let b2 = get_bit(hash[((pos + 1) / 8)], (pos + 1) % 8);

            let trit = (b1 << 1) | b2;
            if trit < 3 {
                trits[sampled] = trit;
                sampled += 1;
            }

            pos += 2;
        }

        trits
    }
}

#[cfg(test)]
mod test_fs {
    use super::SigmaProtocolStatelessFiatShamir;
    use sha3::Keccak256;

    #[test]
    fn instantiate() {
        let seed = b"hello fs 1313e1";
        let public_data = b"this is public";
        let prover_msg = b"this from prover";
        let r = 137usize;

        let trits = SigmaProtocolStatelessFiatShamir::<Keccak256>::sample_trits(seed, public_data, prover_msg, r);
        for trit in trits {
            assert!(trit == 0 || trit == 1 || trit == 2);
        }
    }
}
