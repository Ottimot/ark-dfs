// For benchmark, run:
//     RAYON_NUM_THREADS=N cargo bench --no-default-features --features "std parallel" -- --nocapture
// where N is the number of threads you want to use (N = 1 for single-thread).
use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_ff::PrimeField;
use ark_ff::Field;
use ark_mnt4_298::{Fr as MNT4Fr, MNT4_298};
use ark_mnt4_753::{Fr as MNT4BigFr, MNT4_753};
use ark_mnt6_298::{Fr as MNT6Fr, MNT6_298};
use ark_mnt6_753::{Fr as MNT6BigFr, MNT6_753};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::sonic_pc::SonicKZG10;
use ark_poly_commit::LinearCombination;
use ark_relations::r1cs::ConstraintMatrices;
use ark_std::log2;
use ark_std::{ops::Mul, UniformRand};
use blake2::Blake2s;
use dfs::snark::indexer::Indexer;
use dfs::snark::zk::SRS;
use dfs::snark::R1CSProof;
use dfs::utils::produce_test_r1cs;
use dfs::R1CSInstance;
use rand_chacha::ChaChaRng;

use ark_bn254::{Bn254, Fr as Fr254};
use ark_std::rand::RngCore;

use parser::Parser;

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, ConstraintSystem, SynthesisMode, LinearCombination as LC};
use ark_relations::lc;

const NUM_PROVE_REPEATITIONS: usize = 1;
const NUM_VERIFY_REPEATITIONS: usize = 1;

#[derive(Clone)]
struct DummyCircuit<F: PrimeField> { //Modified to use Field instead of PrimeField -> old version of ark::ff
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}
/*
impl<F: PrimeField> Clone for DummyCircuit<F> {
    fn clone(&self) -> Self {
        DummyCircuit {
            a: self.a.clone(),
            b: self.b.clone(),
            num_variables: self.num_variables.clone(),
            num_constraints: self.num_constraints.clone(),
        }
    }
}
*/

impl<F: PrimeField> DummyCircuit<F> {

    pub fn transform(&self, c: DummyCircuit<F>) -> Result<(ConstraintMatrices<F>, usize, usize, usize, Vec<F>, Vec<F>), SynthesisError> {
        let pcs = ConstraintSystem::new_ref();
        let ics: ConstraintSystemRef<F> = ConstraintSystem::new_ref();
        pcs.set_mode(SynthesisMode::Prove{
            construct_matrices: true,
        });
        c.clone().generate_constraints(pcs.clone())?;
        let (formatted_input_assignment, witness_assignment) = {
            let pcs = pcs.borrow().unwrap();
            (
                pcs.instance_assignment.as_slice().to_vec(),
                pcs.witness_assignment.as_slice().to_vec(),
            )
        };

        //let input: Vec<F> = formatted_input_assignment.into_iter().skip(1).collect();
        //let mut total_input = input.clone();
        //let mut total_input = formatted_input_assignment.clone();
        //total_input.append(&mut witness_assignment);
        c.generate_constraints(ics.clone())?;
        let matrix = ics.to_matrices().unwrap();
        let num_var = ics.num_witness_variables() + ics.num_instance_variables();
        let num_cons = ics.num_constraints();
        let num_input = ics.num_instance_variables();
        Ok((matrix, num_var, num_cons, num_input, formatted_input_assignment, witness_assignment))
    }


}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        
        let a_val = self.a; // Option<F>
        let b_val = self.b; // Option<F>

        let a = cs.new_witness_variable(|| a_val.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| b_val.ok_or(SynthesisError::AssignmentMissing))?;

        
        let c = cs.new_witness_variable(|| {
            let a = a_val.ok_or(SynthesisError::AssignmentMissing)?;
            let b = b_val.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;

        // variabili extra (se richieste)
        for _ in 0..(self.num_variables.saturating_sub(3)) {
            let _ = cs.new_witness_variable(|| a_val.ok_or(SynthesisError::AssignmentMissing))?;
        }

        // num_constraints-1 volte: (a) * (b) = (c)
        for _ in 0..self.num_constraints.saturating_sub(1) {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }
        // ultima riga: 0 * 0 = 0

        //let fake_lc: LC<F> = lc!() + a + b;
        cs.enforce_constraint(lc!(), lc!(), lc!())?;

        // (facoltative) stampe di debug
        // eprintln!("public:   {}", cs.num_instance_variables());
        // eprintln!("witness:  {}", cs.num_witness_variables());
        // eprintln!("constraints: {}", cs.num_constraints());
        Ok(())
    }
    
}



macro_rules! dfs_prove_bench {
    ($bench_name:ident, $bench_field:ty, $bench_pairing_engine:ty) => {
        let mut rng = &mut ark_std::test_rng();
        eprintln!("rng: {:?}", rng.next_u64());

        for num_vars in 12..13 {
            let num_cons = 1 << num_vars;
            // let num_z = 1 << num_vars;
            // let num_wit = 1 << (num_vars - 1);
            let c = DummyCircuit::<$bench_field> {
                a: Some(<$bench_field>::rand(rng)),
                b: Some(<$bench_field>::rand(rng)),
                num_variables: 15,
                num_constraints: num_cons,
            };
            let start_setup = ark_std::time::Instant::now();
            //let path = "Circuiti_prova/Sudoku9x9.arith";
            //let path_input = "Circuiti_prova/Sudoku9x9_Sample_Run1.in";

            let path = "Circuiti_prova/JRPC_simplified_dynamic_optimized.arith";
            let path_input = "Circuiti_prova/JRPC_simplified_dynamic_optimized_11.in";

            let c = Parser::<$bench_field>::new(path.to_string(), path_input.to_string());
            let _cs = ConstraintSystem::<Fr254>::new_ref();

            c.clone().generate_constraints(_cs).expect("generate_constraints failed");
             
            let (a_vec, b_vec, c_vec, num_var, num_cons, num_input, input, witness, _) = c.transform().expect("transform failed");
            let num_var_log = (ark_std::log2(num_var)) as usize;

            let r1cs = R1CSInstance::new(num_cons, num_var_log, num_input, &a_vec, &b_vec, &c_vec);

            

            let srs = SRS::<$bench_pairing_engine, _>::generate_srs(22, 4, rng);

            //eprintln!("srs: {:?}", srs.poly_srs.0.powers_of_g);

            eprintln!("SRS generated");

            let (pk, vk) = Indexer::index_for_prover_and_verifier(&r1cs, &srs);

            eprintln!("PK and VK generated");


           
            eprintln!("Tempo totale di setup: {:?}", final_time_setup);

            let start = ark_std::time::Instant::now();

            /*

             for _ in 0..NUM_PROVE_REPEATITIONS {
                let _ = R1CSProof::new(&r1cs, &pk, &vk, &z, &Vec::new());
            }
            
            */
            let proof = R1CSProof::new(&r1cs, &pk, &vk, &witness, &input);
            //let proof = R1CSProof::new(&r1cs, &pk, &vk, &z, &Vec::new());
            /*
            eprintln!("proof.witness commitment: {:?}", proof.witness_commitment);
            eprintln!("proof.first_sumcheck_msgs -> g_commit: {:?}", proof.first_sumcheck_msgs.g_commit);
            eprintln!("proof.first_sumcheck_msgs -> sumcheck_proof len: {}", proof.first_sumcheck_msgs.sumcheck_proof.len());
            //eprintln!("proof.first_sumcheck_msgs -> poly_info: {:?}", proof.first_sumcheck_msgs.poly_info);
            //eprintln!("proof.first_sumcheck_msgs -> g_proof: {:?}", proof.first_sumcheck_msgs.g_proof);
            //eprintln!("proof.first_sumcheck_msgs -> g_value: {:?}", proof.first_sumcheck_msgs.g_value);
            eprintln!("proof.va: {:?}", proof.va);
            eprintln!("proof.vb: {:?}", proof.vb);
            eprintln!("proof.vc: {:?}", proof.vc);
            eprintln!("proof.second_sumcheck_msgs - g_commit: {:?}", proof.second_sumcheck_msgs.g_commit);
            eprintln!("proof.second_sumcheck_msgs - sumcheck_proof len: {}", proof.second_sumcheck_msgs.sumcheck_proof.len());
            //eprintln!("proof.second_sumcheck_msgs - poly_info: {:?}", proof.second_sumcheck_msgs.poly_info);
            //eprintln!("proof.second_sumcheck_msgs - g_proof: {:?}", proof.second_sumcheck_msgs.g_proof);
            eprintln!("proof.second_sumcheck_msgs - g_value: {:?}", proof.second_sumcheck_msgs.g_value);
            eprintln!("proof.witness_eval: {:?}", proof.witness_eval);
            eprintln!("proof.val_M: {:?}", proof.val_M);
            //eprintln!("proof.witness_proof: {:?}", proof.witness_proof);
            eprintln!("proof.eq_tilde_rx_commitment: {:?}", proof.eq_tilde_rx_commitment);
            eprintln!("proof.eq_tilde_ry_commitment: {:?}", proof.eq_tilde_ry_commitment);
            //eprintln!("proof.lookup_proof: {:?}", proof.lookup_proof);
            eprintln!("Proof generated");
            */
            let final_time = start.elapsed();
            eprintln!("Tempo totale di proof: {:?}", final_time);
            
            let ver_time = ark_std::time::Instant::now();

            for _ in 0..NUM_VERIFY_REPEATITIONS {
                //let result = proof.verify(&vk, &Vec::new());
                let result = proof.verify(&vk, &input);
                eprintln!("Proof verified, {:?}", result);
            }


            let final_ver_time = ver_time.elapsed();
            
        
           
            println!(
                "proving time for 2^{:?} num_cons: {:?}",
                num_vars,
                final_time / NUM_PROVE_REPEATITIONS as u32
            ); 
        }

        // println!(
        //     "per-constraint proving time for {}: {} ns/constraint",
        //     stringify!($bench_pairing_engine),
        //     start.elapsed().as_nanos() / NUM_PROVE_REPEATITIONS as u128 / 65536u128
        // );
    };  
}

macro_rules! dfs_verify_bench {
    ($bench_name:ident, $bench_field:ty, $bench_pairing_engine:ty) => {
        let rng = &mut ark_std::test_rng();
        for num_vars in 3..4 {
            let num_cons = 1 << num_vars;
            // let num_z = 1 << num_vars;
            // let num_wit = 1 << (num_vars - 1);
            let (r1cs, z, _, _, _) = produce_test_r1cs::<$bench_field>(num_vars, rng);
            // R1CSInstance::<$bench_field>::produce_synthetic_r1cs(num_cons, num_z, num_wit, rng);
            // let num_vars = 16 + 3;
            let srs = SRS::<$bench_pairing_engine, _>::generate_srs(num_vars, 4, rng);
            let (pk, vk) = Indexer::index_for_prover_and_verifier(&r1cs, &srs);
            let proof = R1CSProof::new(&r1cs, &pk, &vk, &z, &Vec::new());

            let start = ark_std::time::Instant::now();

            for _ in 0..NUM_VERIFY_REPEATITIONS {
                let _ = proof.verify(&vk, &Vec::new());
            }

            let final_time = start.elapsed();
            println!(
                "verification time for 2^{:?} num_cons: {:?}",
                num_vars,
                final_time / NUM_PROVE_REPEATITIONS as u32
            );

            // println!(
            //     "verifying time for {}: {} ms",
            //     stringify!($bench_pairing_engine),
            //     // start.elapsed().as_nanos() / NUM_VERIFY_REPEATITIONS as u128
            //     start.elapsed().as_micros()
            // );
        }
    };
}
fn bench_prove() {

    dfs_prove_bench!(bn254, Fr254, Bn254);
    //dfs_prove_bench!(bls, BlsFr, Bls12_381);
    // dfs_prove_bench!(mnt4, MNT4Fr, MNT4_298);
    // dfs_prove_bench!(mnt6, MNT6Fr, MNT6_298);
    // dfs_prove_bench!(mnt4big, MNT4BigFr, MNT4_753);
    // dfs_prove_bench!(mnt6big, MNT6BigFr, MNT6_753);
}
fn bench_verify() {
    
    dfs_verify_bench!(bn254, Fr254, Bn254);
    //dfs_verify_bench!(bls, BlsFr, Bls12_381);
    // dfs_verify_bench!(mnt4, MNT4Fr, MNT4_298);
    // dfs_verify_bench!(mnt6, MNT6Fr, MNT6_298);
    // dfs_verify_bench!(mnt4big, MNT4BigFr, MNT4_753);
    // dfs_verify_bench!(mnt6big, MNT6BigFr, MNT6_753);
}

fn main() {
    bench_prove();
    //bench_verify();
}
