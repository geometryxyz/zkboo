/*
    Optimizing XORs: 

        Let's assume that n (number of repetitions) is odd. 
        Verifier has access to 2 out of 3 inputs from zkboo proof
        and we can align those in the following xor relation table: 

        Ex: n = 9
        ____________________________________
        rep | wtns | inst | inst |  preimage
        0   | in_1 | in_2 | in_3 |     x
        1   | in_1 | in_2 | in_3 |     x
        2   | in_1 | in_2 | in_3 |     x
        3   | in_1 | in_2 | in_3 |     x
        4   | in_1 | in_2 | in_3 |     x
        5   | in_1 | in_2 | in_3 |     x
        6   | in_1 | in_2 | in_3 |     x
        7   | in_1 | in_2 | in_3 |     x
        8   | in_1 | in_2 | in_3 |     x
        ____________________________________

        s.t input_1 is always witness and inputs_2&3 are public data. 

        We use the fact that when all (in_1, in_2, in_3) are xored, for odd n, we get just x; 
            - This follows from xor being equal to addition on GF(2). 

        Instead of doing XOR for each repetition: 

            - V computes Rhs = XOR(Rhs, rep_i(in_2, in_3)) for all repetitions outside of the circuit  
    
            - P computes Lhs = XOR(Lhs, rep_i(in_1)) for all repetitions inside the circuit 

        This saves 2/3 amount of: lookups, field (un)packings and bit decompositions
 */

#[cfg(test)]
mod composition_tests {
    use rand::{thread_rng, Rng};

    #[test]
    fn test_lhs_rhs() {
        let mut rng = thread_rng();

        let x: u8 = rng.gen();
        let reps = 9;

        let ins_2: Vec<u8> = (0..reps).map(|_| rng.gen()).collect();
        let ins_3: Vec<u8> = (0..reps).map(|_| rng.gen()).collect();

        let ins_1: Vec<u8> = ins_2.iter().zip(ins_3.iter()).map(|(in_2, in_3)| x ^ in_2 ^ in_3).collect();

        // Verifier computes outside of the circuit
        let rhs = ins_2.iter().zip(ins_3.iter()).map(|(in_2, in_3)| in_2 ^ in_3);
        let rhs = rhs.fold(0, |acc, rhs_i| acc ^ rhs_i);

        // Prover computes inside the circuit
        let lhs = ins_1.iter().fold(0, |acc, rhs_i| acc ^ rhs_i);

        assert_eq!(lhs ^ rhs, x);
    }
}