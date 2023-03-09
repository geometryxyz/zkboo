use crate::gf2_word::GF2Word;


pub fn padding(input: &[u8]) -> Vec<GF2Word<u32>> {
    let mut msg = input.to_vec();
    let length_u64 = (8 * input.len()) as u64; // msg len in bits
    msg.push(0x80); // append one 1 bit and seven 0 bits

    while (msg.len() * 8 + 64) % 512 != 0 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&length_u64.to_be_bytes());

    assert!(msg.len() * 8 % 512 == 0);
    msg.chunks(4)
        .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()).into())
        .collect()
}

#[cfg(test)]
mod test_padding {
    use crate::gadgets::sha256::test_vectors::long::TEST_INPUT as LONG_TEST;
    use crate::gadgets::sha256::test_vectors::short::TEST_INPUT as SHORT_TEST;

    use super::padding;
    #[test]
    fn short_padding() {
        let input = "abc".as_bytes();
        let padded_input = padding(input);
        for (&word, &expected_word) in padded_input.iter().zip(SHORT_TEST.iter()) {
            assert_eq!(word.value, expected_word);
        }
    }

    #[test]
    fn long_padding() {
        let input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
        let padded_input = padding(input);
        for (&word, &expected_word) in padded_input.iter().zip(LONG_TEST.iter()) {
            assert_eq!(word.value, expected_word);
        }
    }
}
