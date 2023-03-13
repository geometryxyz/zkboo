#[macro_use]
extern crate criterion;

use criterion::{BenchmarkId, Criterion};
use rand::{rngs::ThreadRng, thread_rng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use zkboo::{
    circuit::{Circuit, Output},
    data_structures::Proof,
    error::Error,
    gadgets::sha256::{init_iv, mpc_sha256_block, mpc_sha256_block_verify, padding, State},
    gf2_word::GF2Word,
    party::Party,
    prover::Prover,
    verifier::Verifier,
};

fn criterion_benchmark(c: &mut Criterion) {
    pub struct Sha256Circuit {
        preimage: String,
    }

    impl Circuit<u32> for Sha256Circuit {
        fn compute(&self, input: &[u8]) -> Vec<GF2Word<u32>> {
            assert_eq!(input.len(), 0);
            // create a Sha256 object
            let mut hasher = Sha256::new();

            // write input message
            hasher.update(self.preimage.as_bytes());

            // read hash digest and consume hasher
            let digest = hasher.finalize().to_vec();

            let mut res = Vec::with_capacity(8);
            for i in 0..8 {
                let word = u32::from_be_bytes(digest[(4 * i)..(4 * i + 4)].try_into().unwrap());
                res.push(word.into())
            }

            res
        }

        fn compute_23_decomposition(
            &self,
            p1: &mut Party<u32>,
            p2: &mut Party<u32>,
            p3: &mut Party<u32>,
        ) -> (Vec<GF2Word<u32>>, Vec<GF2Word<u32>>, Vec<GF2Word<u32>>) {
            let p1_words = padding(&p1.view.input);
            let p2_words = padding(&p2.view.input);
            let p3_words = padding(&p3.view.input);

            // Initialize state
            let mut p1_state: State = init_iv().to_vec().into();
            let mut p2_state: State = init_iv().to_vec().into();
            let mut p3_state: State = init_iv().to_vec().into();

            // Process padded input chunk by chunk
            let iter_chunks = p1_words
                .chunks(16)
                .zip(p2_words.chunks(16))
                .zip(p3_words.chunks(16));

            for ((p1_words, p2_words), p3_words) in iter_chunks {
                (p1_state, p2_state, p3_state) = mpc_sha256_block(
                    &p1_words.try_into().unwrap(),
                    &p2_words.try_into().unwrap(),
                    &p3_words.try_into().unwrap(),
                    &(p1_state, p2_state, p3_state),
                    p1,
                    p2,
                    p3,
                );
            }

            (p1_state.to_vec(), p2_state.to_vec(), p3_state.to_vec())
        }

        fn simulate_two_parties(
            &self,
            p: &mut Party<u32>,
            p_next: &mut Party<u32>,
        ) -> Result<(Output<u32>, Output<u32>), Error> {
            let p_words = padding(&p.view.input);
            let p_next_words = padding(&p_next.view.input);

            // Initialize state
            let mut p_state: State = init_iv().to_vec().into();
            let mut p_next_state: State = init_iv().to_vec().into();

            // Process padded input chunk by chunk
            let iter_chunks = p_words.chunks(16).zip(p_next_words.chunks(16));

            for (p_words, p_next_words) in iter_chunks {
                (p_state, p_next_state) = mpc_sha256_block_verify(
                    &p_words.try_into().unwrap(),
                    &p_next_words.try_into().unwrap(),
                    &(p_state.to_vec().into(), p_next_state.to_vec().into()),
                    p,
                    p_next,
                )?;
            }

            Ok((p_state.to_vec(), p_next_state.to_vec()))
        }

        fn party_input_len(&self) -> usize {
            16
        }

        fn party_output_len(&self) -> usize {
            8
        }

        fn num_of_mul_gates(&self) -> usize {
            let num_chunks = padding(self.preimage.as_bytes()).len();

            let msg_schedule = 3 * 48;
            let compression = 9 * 64;
            let digest = 8;

            (msg_schedule + compression + digest) * num_chunks
        }
    }

    const SIGMA: usize = 1;
    fn prover(
        num_blocks: usize,
    ) -> (
        Sha256Circuit,
        Proof<u32, Keccak256, SIGMA>,
        Vec<GF2Word<u32>>,
    ) {
        let mut rng = thread_rng();

        let string =
            String::from("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl");
        let mut preimage = String::from("");
        for _ in 0..num_blocks {
            preimage = format!("{}{}", preimage, string);
        }

        let circuit = Sha256Circuit {
            preimage: preimage.clone(),
        };

        let output = circuit.compute(&[]);

        let proof = Prover::<u32, ChaCha20Rng, Keccak256>::prove::<ThreadRng, SIGMA>(
            &mut rng,
            preimage.as_bytes(),
            &circuit,
            &output,
        )
        .unwrap();

        (circuit, proof, output)
    }

    fn verifier(
        circuit: &Sha256Circuit,
        proof: &Proof<u32, Keccak256, SIGMA>,
        output: &Vec<GF2Word<u32>>,
    ) {
        Verifier::<u32, ChaCha20Rng, Keccak256>::verify(proof, circuit, output).unwrap();
    }

    let num_blocks_range = 1..=10;

    let mut prover_group = c.benchmark_group("sha256-prover");
    prover_group.sample_size(10);
    for num_blocks in num_blocks_range.clone() {
        prover_group.bench_with_input(
            BenchmarkId::from_parameter(num_blocks),
            &num_blocks,
            |b, &num_blocks| b.iter(|| prover(num_blocks)),
        );
    }
    prover_group.finish();

    let mut verifier_group = c.benchmark_group("sha256-verifier");
    verifier_group.sample_size(10);
    for num_blocks in num_blocks_range {
        let (circuit, proof, output) = prover(num_blocks);
        verifier_group.bench_with_input(
            BenchmarkId::from_parameter(num_blocks),
            &(circuit, proof, output),
            |b, (circuit, proof, output)| b.iter(|| verifier(circuit, proof, output)),
        );
    }
    verifier_group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
