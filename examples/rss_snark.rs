#![allow(warnings)]
use ark_bls12_381::Fr;
//use ark_bls12_381::Fr;
use ark_std::{cfg_chunks, cfg_chunks_mut, cfg_into_iter, cfg_iter};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::{Parser, Subcommand};
use mpi::{
    datatype::{Partition, PartitionMut},
    topology::Process,
    Count,
};
use mpi::{request, traits::*};
// use mpi_snark::worker::WorkerState;

use std::{
    cmp::max, fs::{File, OpenOptions}, io::{self, Read, Write}, num::NonZeroUsize, path::{self, PathBuf}
};

use mimalloc::MiMalloc;

use crossbeam::thread;
use itertools::{merge, Itertools};
use rayon::prelude::*;

//use ark_bls12_381::Config;
//use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{UniformRand,PrimeField};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::path::Path;
use core::num;
use std::mem;
use std::{collections::HashMap, rc::Rc, process::{Command as ImpCommand, Stdio}};

use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, One, Zero};
use ark_linear_sumcheck::ml_sumcheck::protocol::verifier::SubClaim;
use ark_linear_sumcheck::ml_sumcheck::protocol::IPForMLSumcheck;
use ark_linear_sumcheck::ml_sumcheck::protocol::PolynomialInfo;
use ark_linear_sumcheck::ml_sumcheck::{protocol::ListOfProductsOfPolynomials, MLSumcheck};
use ark_linear_sumcheck::rng::{Blake2s512Rng, FeedableRNG};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_poly_commit::challenge::ChallengeGenerator;

use ark_poly_commit::multilinear_pc::{
    data_structures::Commitment, data_structures::CommitterKey, data_structures::VerifierKey,
    MultilinearPC,
};
use ark_std::fs;
use dfs::{mpc_snark::worker, subprotocols::loglookup::LogLookupProof};
use dfs::utils::generate_dumb_sponge;
use dfs::{mpc::rss::RssPoly, mpi_snark::worker::PublicProver};
use dfs::{mpc::utils::generate_rss_share_randomness, mpc_snark::worker::DistributedRSSProverKey};
use dfs::{mpc_snark::coordinator, subprotocols::loglookup::sumcheck_polynomial_list};
use dfs::{mpi_snark::coordinator::mpi_batch_open_poly_coordinator, utils::produce_test_r1cs};
use dfs::{mpi_utils::send_responses, utils::split_ipk};
use dfs::{snark::indexer::Indexer, R1CSInstance};
use dfs::{snark::zk::SRS, utils::split_r1cs};

use dfs::utils::{
    aggregate_comm, aggregate_eval, aggregate_poly, boost_degree, combine_comm, distributed_open,
    generate_eq, map_poly, merge_list_of_distributed_poly, merge_proof, normalized_multiplicities,
    partial_generate_eq, split_ck, split_poly, split_vec, two_pow_n,
};
use dfs::{end_timer_buf, start_timer_buf};
use dfs::{VerificationError, VerificationResult};
use rand::RngCore;

use dfs::mpc::rss::SSRandom;
use dfs::mpc::utils::generate_poly_shares_rss;
use dfs::mpc_snark::coordinator::PrivateProver;
use dfs::mpi_snark::coordinator::{mpi_poly_commit_coordinator, mpi_sumcheck_coordinator};
use dfs::mpi_snark::worker::{mpi_batch_open_poly_worker, mpi_sumcheck_worker};
use dfs::mpi_utils::{gather_responses, receive_requests, scatter_requests};
use dfs::snark::indexer::IndexProverKey;
use dfs::snark::indexer::IndexVerifierKey;
use dfs::snark::prover::ProverMessage;
use dfs::snark::verifier::DFSVerifier;
use dfs::snark::verifier::VerifierState;
use dfs::snark::{batch_open_poly, batch_verify_poly, BatchOracleEval, OracleEval};
use dfs::transcript::{get_scalar_challenge, get_vector_challenge};
use parser::Parser as circuit_generator;
use ark_bn254::{Bn254, Fr as Fr254};

use anyhow::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use ark_std::time::Instant;

use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError, Variable, LinearCombination}, 
};


#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;


#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct DistributedRootKey<E: Pairing> {
    pub ipk: IndexProverKey<E>,
    pub pub_ipk: IndexProverKey<E>,
    pub ivk: IndexVerifierKey<E>,
}

#[derive(Parser)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Setup {
        #[clap(long, value_name = "NUM")]
        log_instance_size: usize,

        #[clap(long, value_name = "NUM")]
        log_num_workers_per_party: usize,

        #[clap(long, value_name = "NUM")]
        log_num_public_workers: usize,

        #[clap(long, value_name = "DIR")]
        key_out: PathBuf,
    },

    Work {
        /// Path to the coordinator key package
        #[clap(long, value_name = "DIR")]
        key_file: PathBuf,

        #[clap(long, value_name = "NUM")]
        log_instance_size: usize,

        /// The number of workers who will do the committing and proving. Each worker has 1 core.
        #[clap(long, value_name = "NUM")]
        log_num_workers_per_party: usize,

        #[clap(long, value_name = "NUM")]
        log_num_public_workers: usize,

        #[clap(long, value_name = "NUM")]
        worker_id: usize,

        #[clap(long, value_name = "NUM")]
        local: usize,
    },
}

pub async fn recv_ark<T, R>(stream: &mut R) -> Result<T>
where
    T: CanonicalDeserialize,
    R: AsyncReadExt + Unpin,
{
    let len = stream.read_u32().await? as usize;

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    let value = T::deserialize_compressed(&*buf)?; // or deserialize_uncompressed
    Ok(value)
}

fn run(program: &str, args: &[&str]) -> io::Result<()> {
    eprintln!("$ {} {}", program, args.join(" "));

    let status = ImpCommand::new(program)
        .args(args)
        
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?; 

    if status.success() {
        Ok(())
    } else {
        
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("{} exited with status {}", program, status),
        ))
    }
}

fn sep() -> &'static str { if cfg!(windows) { ";" } else { ":" } }

fn run_string_circuit(
    transcript_path: &Path,
    merkle_path: &Path,
    allowed: &str
) -> Result<(PathBuf, PathBuf)> {
    let transcript_path = fs::canonicalize(transcript_path)
        .with_context(|| format!("missing transcript: {}", transcript_path.display()))?;
    // Captured transcripts live in <app_dir>/files.
    let app_dir = transcript_path.parent().and_then(|dir| dir.parent())
        .context("transcript needs an application directory above files")?;
    let merkle_path = fs::canonicalize(merkle_path).context("missing Merkle policy")?;
    anyhow::ensure!(transcript_path.is_file(), "missing transcript: {}", transcript_path.display());
    anyhow::ensure!(merkle_path.is_file(), "missing Merkle policy: {}", merkle_path.display());

    // Setup provides both files, which may be bind-mounted read-only.
    let circuit_path = app_dir.join("circuits/JRPC_complete_dynamic_optimized.arith");
    let layout_path = app_dir.join("circuits/input_layout_complete.txt");
    for path in [&circuit_path, &layout_path] {
        let metadata = fs::metadata(path)
            .with_context(|| format!("missing setup file: {}", path.display()))?;
        anyhow::ensure!(metadata.is_file() && metadata.len() > 0,
            "invalid setup file: {}", path.display());
    }

    let output_dir = app_dir.join("coordinator-runtime/files");
    fs::create_dir_all(&output_dir)?;
    let input_path = output_dir.join("JRPC_complete_dynamic_randomid + pktnum_optimized.pub.in");
    match fs::remove_file(&input_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("remove stale output {}", input_path.display())),
    }

    let status = ImpCommand::new("java")
        .current_dir(app_dir.join("input_generator"))
        .arg("JRPCInputGenerator")
        .arg("pub")
        .arg(&layout_path)
        .arg(&transcript_path)
        .arg(&merkle_path)
        .arg("run_command")
        .arg(&input_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("launch JRPCInputGenerator")?;
    anyhow::ensure!(status.success(), "JRPCInputGenerator failed: {status}");
    let metadata = fs::metadata(&input_path)
        .with_context(|| format!("missing generated input: {}", input_path.display()))?;
    anyhow::ensure!(metadata.is_file() && metadata.len() > 0,
        "empty generated input: {}", input_path.display());

    Ok((circuit_path, input_path))
}


fn main() {

    let args = Args::parse();

    match args.command {
        Command::Setup {
            log_instance_size,
            log_num_workers_per_party,
            log_num_public_workers,
            key_out,
        } => setup::<Bn254>(
            key_out,
            log_instance_size,
            log_num_workers_per_party,
            log_num_public_workers,
        ),
        Command::Work {
            key_file,
            log_num_workers_per_party,
            log_num_public_workers,
            log_instance_size,
            worker_id,
            local,
        } => {
            work::<Bn254>(
                log_num_workers_per_party,
                log_instance_size,
                key_file,
                worker_id,
                log_num_public_workers,
                local,
            );
        }
    }
}


fn setup<E: Pairing>(
    origin_key_out_path: PathBuf,
    log_instance_size: usize,
    log_num_workers_per_party: usize,
    _log_num_public_workers: usize,
) {
    eprintln!("Setup started");
    use ark_std::time::Instant;
    let time = Instant::now();
    let D: usize = log_instance_size;

    //let mut rng = StdRng::seed_from_u64(12);
    let mut rng = &mut ark_std::test_rng();
    eprintln!("rng: {:?}", rng.next_u64());

    //eprintln!("num_vars: {}", r1cs.num_vars);

    //let path = "Circuiti_prova/Sudoku9x9.arith";
    //let path_input = "Circuiti_prova/Sudoku9x9_Sample_Run1.in";

    ///NOTA: -> log 10: simplified offset | log 11: simplified dyn | log 12: full offset | log 13: full dyn | log 14: complete dynamic 300 bytes
    
    let time_lettura = Instant::now();
    let path = "files/JRPC_complete_dynamic_optimized.arith";
    let path_input = "";

    let cwd = std::env::current_dir().expect("read setup working directory");
    let xjsnark_dir = cwd.ancestors()
        .map(|dir| dir.join("xjsnark_decompiled"))
        .find(|dir| dir.is_dir())
        .expect("run setup from the repository or a directory containing xjsnark_decompiled");
    let classpath = std::env::join_paths([
        xjsnark_dir.join("xjsnark_bin"),
        xjsnark_dir.join("backend_bin_mod"),
        xjsnark_dir.join("backend_bin_mod/*"),
    ]).expect("build Java classpath");

    fs::create_dir_all("files").expect("create circuit output directory");
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove stale circuit {path}: {error}"),
    }
    // The bundled class always generates the circuit; only run/pub evaluate inputs.
    // main still reads all six arguments, so setup needs unused placeholders.
    run("java", &[
        "-cp", classpath.to_str().expect("Java classpath must be UTF-8"),
        "xjsnark.PolicyCheck.JRPC_complete_dynamic",
        "setup", "", "", "run_command", "", "1",
    ]).expect("generate setup circuit");
    // Java can print an I/O error and still exit successfully.
    let output = fs::metadata(path).expect("Java did not generate the setup circuit");
    assert!(output.is_file() && output.len() > 0, "empty setup circuit: {path}");

    let c = circuit_generator::<Fr254>::new(path.to_string(), path_input.to_string());
    let _cs = ConstraintSystem::<Fr254>::new_ref();

    c.clone().generate_constraints(_cs).expect("generate_constraints failed");

    let (a_vec, b_vec, c_vec, num_var, num_cons, num_input, input, witness, align_len) = c.transform().expect("transform failed");
    eprintln!("align_len: {}", align_len);
    
    let num_var_log = (ark_std::log2(num_var)) as usize;
    let num_cons_log = (ark_std::log2(num_cons)) as usize;
    let align_len_log = (ark_std::log2(align_len)) as usize;
    let need = max(num_var_log, max(align_len_log, num_cons_log));
    let r1cs = R1CSInstance::new(num_cons, num_var_log, num_input, &a_vec, &b_vec, &c_vec);

    let time_lettura_final = time_lettura.elapsed(); 
    
    
    let time_creazione_pk = Instant::now();
    
    //let (r1cs, z, za, zb, zc) = produce_test_r1cs(12, &mut rng);
    //let z_vec = z.clone();
    let srs = SRS::<Bn254, _>::generate_srs(need, 4, &mut rng);
    
    let (pk, vk) = Indexer::index_for_prover_and_verifier(&r1cs, &srs);
    
    let final_time_creazione_pk = time_creazione_pk.elapsed();

    //NOTE: witness and input shares not in the setup anymore!
    /* 
    let mut z_eval = cfg_iter!(&input)
        .chain(&witness.clone())
        .copied()
        .collect::<Vec<Fr254>>();

    z_eval.resize((1 << pk.padded_num_var), Fr254::zero());
    
    // CORRECT: Create witness polynomial with zeros in public input positions
    let mut witness_padded = vec![Fr254::zero(); num_input]; // Zeros for public input positions
    witness_padded.extend(witness.clone()); // Actual witness values
    witness_padded.resize((1 << pk.padded_num_var), Fr254::zero()); // Pad to full size
    
    // CORRECT: Only secret-share the WITNESS portion, not the public input
    let witness_poly = DenseMultilinearExtension::from_evaluations_vec(
        pk.padded_num_var, 
        witness_padded.clone()
    );

    let (mut witness_share_0, mut witness_share_1, mut witness_share_2) = generate_poly_shares_rss(&witness_poly, &mut rng);
    

    //eprintln!("z_eval before pad: {}", z_eval.len());
    //eprintln!("to_be_padded: {}", pk.padded_num_var);

    let z_vec = z_eval.clone();
    //z_eval.resize(pk.padded_num_var.pow2(), Fr254::zero());


    /*MODIFICA SETUP -> PRIMA SPLIT DI Z + SHARES, POI CALCOLO DI Z_A/B/C su shares */

    //let z_vec = split_vec(&z_vec, P_W);
    let z = DenseMultilinearExtension::from_evaluations_vec(16, z_vec.clone());
    let (z_share_0, z_share_1, z_share_2) = generate_poly_shares_rss(&z, &mut rng);

    let witness_0 = RssPoly::<Bn254>::new(0, witness_share_0.clone(), witness_share_1.clone());
    let witness_1 = RssPoly::<Bn254>::new(1, witness_share_1.clone(), witness_share_2.clone());
    let witness_2 = RssPoly::<Bn254>::new(2, witness_share_2.clone(), witness_share_0.clone());


    let mut za_share_0 = vec![Fr254::zero(); z_vec.len()];
    let mut zb_share_0 = vec![Fr254::zero(); z_vec.len()];
    let mut zc_share_0 = vec![Fr254::zero(); z_vec.len()];

    let mut za_share_1 = vec![Fr254::zero(); z_vec.len()];
    let mut zb_share_1 = vec![Fr254::zero(); z_vec.len()];
    let mut zc_share_1 = vec![Fr254::zero(); z_vec.len()];

    let mut za_share_2 = vec![Fr254::zero(); z_vec.len()];
    let mut zb_share_2 = vec![Fr254::zero(); z_vec.len()];
    let mut zc_share_2 = vec![Fr254::zero(); z_vec.len()];


    for entry in &r1cs.A.M {
        za_share_0[entry.row] += entry.val * z_share_0.evaluations[entry.col];
        za_share_1[entry.row] += entry.val * z_share_1.evaluations[entry.col];
        za_share_2[entry.row] += entry.val * z_share_2.evaluations[entry.col];
    }
    for entry in &r1cs.B.M {
        zb_share_0[entry.row] += entry.val * z_share_0.evaluations[entry.col];
        zb_share_1[entry.row] += entry.val * z_share_1.evaluations[entry.col];
        zb_share_2[entry.row] += entry.val * z_share_2.evaluations[entry.col];
    }
    for entry in &r1cs.C.M {
        zc_share_0[entry.row] += entry.val * z_share_0.evaluations[entry.col];
        zc_share_1[entry.row] += entry.val * z_share_1.evaluations[entry.col];
        zc_share_2[entry.row] += entry.val * z_share_2.evaluations[entry.col];
    }


    let mut za_share_0 = DenseMultilinearExtension::from_evaluations_vec(pk.padded_num_var, za_share_0.clone());
    let mut zb_share_0 = DenseMultilinearExtension::from_evaluations_vec(pk.padded_num_var, zb_share_0.clone());
    let mut zc_share_0 = DenseMultilinearExtension::from_evaluations_vec(pk.padded_num_var, zc_share_0.clone());

    let mut za_share_1 = DenseMultilinearExtension::from_evaluations_vec(pk.padded_num_var, za_share_1.clone());
    let mut zb_share_1 = DenseMultilinearExtension::from_evaluations_vec(pk.padded_num_var, zb_share_1.clone());
    let mut zc_share_1 = DenseMultilinearExtension::from_evaluations_vec(pk.padded_num_var, zc_share_1.clone());

    let mut za_share_2 = DenseMultilinearExtension::from_evaluations_vec(pk.padded_num_var, za_share_2.clone());
    let mut zb_share_2 = DenseMultilinearExtension::from_evaluations_vec(pk.padded_num_var, zb_share_2.clone());
    let mut zc_share_2 = DenseMultilinearExtension::from_evaluations_vec(pk.padded_num_var, zc_share_2.clone());

    /*FINE MODIFICA */

    /*

    //eprintln!("z_eval_len: {}", z_eval.len());
    let z = DenseMultilinearExtension::from_evaluations_vec(pk.padded_num_var, z_eval);
    //let mut z = input.clone();
    //z.extend(witness.iter().cloned());

    let time_delegabile = Instant::now();

    let mut za = vec![Fr254::zero(); z_vec.len()];
    let mut zb = vec![Fr254::zero(); z_vec.len()];
    let mut zc = vec![Fr254::zero(); z_vec.len()];

    //assert_eq!(r1cs.num_vars.log_2(), num_variables);
    for entry in &r1cs.A.M {
        za[entry.row] += entry.val * z.evaluations[entry.col];
    }
    for entry in &r1cs.B.M {
        zb[entry.row] += entry.val * z.evaluations[entry.col];
    }
    for entry in &r1cs.C.M {
        zc[entry.row] += entry.val * z.evaluations[entry.col];
    }

    let time_delegabile = time_delegabile.elapsed();

    eprintln!("Time delegabile: {:?}", time_delegabile);


    
    eprintln!("a_vec primi 5: {:?}", &za[0..5]);
    eprintln!("b_vec primi 5: {:?}", &zb[0..5]);
    eprintln!("c_vec primi 5: {:?}", &zc[0..5]);

    
    */

    */
   

    // let P: usize = log_num_public_workers;
    // let P_W: usize = log_num_workers_per_party;

    let time_keygen = Instant::now();
    for P_W in 0..log_num_workers_per_party {
        let P: usize = P_W + 1;
        //let P = 0;

        let mut key_out_path = origin_key_out_path.clone();

        fs::create_dir(
            "inst_folder/inst_".to_owned()
                + &log_instance_size.to_string()
                + "_"
                + &P_W.to_string()
                + "_"
                + &P.to_string(),
        );
        key_out_path.push(
            "inst_".to_owned()
                + &log_instance_size.to_string()
                + "_"
                + &P_W.to_string()
                + "_"
                + &P.to_string()
                + "/test",
        );

        let (ipk_vec, root_ipk) = split_ipk(&pk, P_W);

        let (pub_ipk_vec, pub_root_ipk) = split_ipk(&pk, P);
     


        /*
        for (i, ((((v_a, v_b), v_c), row), col)) in pub_ipk_vec[0]
                .val_a
                .evaluations
                .iter()
                .zip(pub_ipk_vec[0].val_b.evaluations.iter())
                .zip(pub_ipk_vec[0].val_c.evaluations.iter())
                .zip(pub_ipk_vec[0].row.iter())
                .zip(pub_ipk_vec[0].col.iter())
                .enumerate()
            {

                if *row > pub_ipk_vec[0].len() || *col > pub_ipk_vec[0].len() {
                    eprintln!("Error at index {}: row {}, col {}", i, *row, *col);
                }
            }
        */
        //eprintln!("pub_ipk_vec_row_2: {}", pub_ipk_vec[1].row.len());
        //eprintln!("pub_ipk_vec_col_2: {}", pub_ipk_vec[1].col.len());
        //eprintln!("num_var: {:?}", r1cs.num_variables);
        // let r1cs_vec = split_r1cs(&r1cs, P);

        /*COMMENTATO PER LA MODIFICA
        let z_vec = split_vec(&z_vec, P_W);
        let za_vec = split_vec(&za, P_W);
        let zb_vec = split_vec(&zb, P_W);
        let zc_vec = split_vec(&zc, P_W);
        let num_vars = r1cs.num_vars - P_W;
        //let num_vars = num_var_log - P_W;

        */

        let mut cnt = 0;

        for i in 0..1 << P_W {
            /*
            eprintln!("Esecuzione con P_W = {}", i);
            let z = DenseMultilinearExtension::from_evaluations_vec(num_vars, z_vec[i].clone());
            let za = DenseMultilinearExtension::from_evaluations_vec(num_vars, za_vec[i].clone());
            let zb = DenseMultilinearExtension::from_evaluations_vec(num_vars, zb_vec[i].clone());
            let zc = DenseMultilinearExtension::from_evaluations_vec(num_vars, zc_vec[i].clone());

            let (z_share_0, z_share_1, z_share_2) = generate_poly_shares_rss(&z, &mut rng);
            let (za_share_0, za_share_1, za_share_2) = generate_poly_shares_rss(&za, &mut rng);
            let (zb_share_0, zb_share_1, zb_share_2) = generate_poly_shares_rss(&zb, &mut rng);
            let (zc_share_0, zc_share_1, zc_share_2) = generate_poly_shares_rss(&zc, &mut rng);

            */

            /*

            let z_0 = RssPoly::<Bn254>::new(0, z_share_0.clone(), z_share_1.clone());
            let za_0 = RssPoly::<Bn254>::new(0, za_share_0.clone(), za_share_1.clone());
            let zb_0 = RssPoly::<Bn254>::new(0, zb_share_0.clone(), zb_share_1.clone());
            let zc_0 = RssPoly::<Bn254>::new(0, zc_share_0.clone(), zc_share_1.clone());

            let z_1 = RssPoly::<Bn254>::new(1, z_share_1.clone(), z_share_2.clone());
            let za_1 = RssPoly::<Bn254>::new(1, za_share_1.clone(), za_share_2.clone());
            let zb_1 = RssPoly::<Bn254>::new(1, zb_share_1.clone(), zb_share_2.clone());
            let zc_1 = RssPoly::<Bn254>::new(1, zc_share_1.clone(), zc_share_2.clone());

            let z_2 = RssPoly::<Bn254>::new(2, z_share_2.clone(), z_share_0.clone());
            let za_2 = RssPoly::<Bn254>::new(2, za_share_2.clone(), za_share_0.clone());
            let zb_2 = RssPoly::<Bn254>::new(2, zb_share_2.clone(), zb_share_0.clone());
            let zc_2 = RssPoly::<Bn254>::new(2, zc_share_2.clone(), zc_share_0.clone());


            */

            let pk_0 = DistributedRSSProverKey {
                ipk: ipk_vec[i].clone(),
                pub_ipk: pub_ipk_vec[cnt].clone(),
                z: None,
                witness: None,
                za: None,
                zb: None,
                zc: None,
                num_variables: r1cs.num_vars,
                //num_variables: num_var_log,
                seed_0: "seed 0".to_string(),
                seed_1: "seed 1".to_string(),
                r1cs: r1cs.clone(),
            };  
            
           
            
            if cnt < (1 << P) - 1 {
                cnt = cnt + 1;
            }

            let pk_1 = DistributedRSSProverKey {
                ipk: ipk_vec[i].clone(),
                pub_ipk: pub_ipk_vec[cnt].clone(),
                z: None,
                witness: None,
                za: None,
                zb: None,
                zc: None,
                num_variables: r1cs.num_vars,
                //num_variables: num_var_log,
                seed_0: "seed 1".to_string(),
                seed_1: "seed 2".to_string(),
                r1cs: r1cs.clone(),
            };

         
            
            if cnt < (1 << P) - 1 {
                cnt = cnt + 1;
            }

            let pk_2 = DistributedRSSProverKey {
                ipk: ipk_vec[i].clone(),
                pub_ipk: pub_ipk_vec[cnt].clone(),
                z: None,
                witness: None,
                za: None,
                zb: None,
                zc: None,
                num_variables: r1cs.num_vars,
                //num_variables: num_var_log,
                seed_0: "seed 2".to_string(),
                seed_1: "seed 0".to_string(),
                r1cs: r1cs.clone(),
            };
            
            if cnt < (1 << P) - 1 {
                cnt = cnt + 1;
            }



            let pk_vec = vec![pk_0, pk_1, pk_2];
    

            for j in 0..3 {
                let mut buf = Vec::new();
                pk_vec[j].serialize_uncompressed(&mut buf).unwrap();

                let mut file_name = key_out_path.clone();
                file_name.set_extension((3 * i + j).to_string());

                let mut f = File::create(&file_name)
                    .expect(&format!("could not create file {:?}", file_name));
                f.write_all(&buf).unwrap();
            }

        }

        {
            let mut buf = Vec::new();
            let pk = DistributedRootKey {
                ipk: root_ipk,
                pub_ipk: pub_root_ipk,
                ivk: vk.clone(),
            };
            pk.serialize_uncompressed(&mut buf).unwrap();
            let mut file_name = key_out_path.clone();
            file_name.set_extension("root");
            let mut f =
                File::create(&file_name).expect(&format!("could not create file {:?}", file_name));
            f.write_all(&buf).unwrap();
        }

        
    

        

    }

    let final_time_keygen = time_keygen.elapsed();
    eprintln!("Keygen finished in {:?}", final_time_keygen);

    let final_time = time.elapsed();
    eprintln!("Setup finished in {:?}", final_time);
}



#[tokio::main(flavor = "current_thread")]
async fn work<E: Pairing<ScalarField = Fr254>>(
    log_num_workers_per_party: usize,
    log_instance_size: usize,
    key_file: PathBuf,
    mut worker_id: usize,
    log_num_public_workers: usize,
    local: usize,
){
    let mut send_size = 0;
    let mut recv_size = 0;

    let (universe, _) = mpi::initialize_with_threading(mpi::Threading::Funneled).unwrap();
    let world = universe.world();
    let root_rank = 0;
    let root_process = world.process_at_rank(root_rank);
    let rank = world.rank();
    let size = world.size();
    /*
    #[cfg(feature = "parallel")]
    {
        rayon::ThreadPoolBuilder::new()
            .num_threads(16)
            .build_global()
            .unwrap();

        println!("Rank {rank}: Rayon num threads = {}", rayon::current_num_threads());
    }
    */
    println!("Rank {rank}: Rayon num threads = {}", rayon::current_num_threads());
    let mut log = Vec::new();
    let very_start = start_timer_buf!(log, || format!("Node {rank}: Beginning work"));

    // if rank == root_rank {
    // Deserialize the proving keys

    println!("running mode: {}", local);

    if local == 0 {
        println!("worker id: {}", worker_id);
    } else {
        println!("worker id: {}", rank);
    }

    if (local == 0 && worker_id == 0) || (local == 1 && rank == root_rank) {
        let proving_keys = {
            let mut buf = Vec::new();

            let mut file_name = key_file.clone();
            file_name.set_extension("root");

            let mut f =
                File::open(&file_name).expect(&format!("couldn't open file {:?}", key_file));
            let _ = f.read_to_end(&mut buf);
            let buf_slice = buf.as_slice();

            let pk =
                DistributedRootKey::<E>::deserialize_uncompressed_unchecked(buf_slice).unwrap();
            pk
        };

        let listener = TcpListener::bind(format!("0.0.0.0:8220")).await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();

        // Receive client_random and packet_number from client
        let mut client_random = vec![0u8; 32]; // ClientHello random is 32 bytes
        stream.read_exact(&mut client_random).await.unwrap();

        //client_random = hex::encode(client_random);

        let packet_number = 1;
        // Initial proof
        let start = start_timer_buf!(log, || format!("Coord: construct coordinator proof"));

        let default_response = "ready".to_string();
        let responses_chunked: Vec<_> = gather_responses(
            &mut log,
            &("mpi_snark_coordinator_".to_owned() + "_start"),
            size,
            &root_process,
            default_response,
        );

        

        let time = Instant::now();

        let (proof, coordinator_time) = dfs::mpc_snark::coordinator::PrivateProver::new(
            &mut log,
            "mpi_snark_coordinator_",
            size,
            &root_process,
            log_num_workers_per_party,
            log_num_public_workers,
            &proving_keys.ipk,
            &proving_keys.pub_ipk,
            &proving_keys.ivk,
            dfs::mpc::utils::ShareType::Rss,
        );

        //

        let final_time = time.elapsed();
        let proving_time = final_time.as_micros();
        println!("proving time: {:?}", final_time);
        println!("coordinator time: {:?}", coordinator_time);
        
        end_timer_buf!(log, start);

        /********************************let verification = proof.verify(&proving_keys.ivk, &input);
        eprintln!("verification result: {:?}", verification);*******************************************/
        /***************************************************************************/
        
        let path_transcript = "app/measurments/meas.csv";
        //let path = "app/Circuiti_prova/SHA256_optimized.arith";
        //let path_input = "app/Circuiti_prova/SHA256_Sample_Run1_optimized.in";
        //let path_input = "";
        //let path = "Circuiti_prova/Sudoku9x9.arith";
        //let path_input = "Circuiti_prova/Sudoku9x9_Sample_Run1.in";
        //let path_input = "Circuiti_prova/Sudoku9x9_Sample_Run1.in";
    
        
        
        
        let circuit = "JRPC_complete_dynamic";
        let client_random_hex = client_random.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let packet_number_str = packet_number.to_string();
        let transcript_file = format!("/app/app/files/transcript_{}{}.txt", client_random_hex, 1);
        let merkle = "/app/app/merkle_tree/test_wildcard_pre.txt";

        // Convert binary client_random to a hex string and the packet number to a string,
        // because Command::arg requires types that can be seen as OS strings.
      
        let allowed = "";

        
        let (circuit_path, input_path) = run_string_circuit(
            Path::new(&transcript_file), Path::new(merkle), allowed,
        ).expect("generate public inputs");
        

        
        let c = circuit_generator::<<E as Pairing>::ScalarField>::new(
            circuit_path.to_string_lossy().into_owned(),
            input_path.to_string_lossy().into_owned(),
        );
        let cs = ConstraintSystem::<Fr254>::new_ref();
        c.clone().generate_constraints(cs).expect("generate_constraints failed");
        
        let (a_vec, b_vec, c_vec, num_var, num_cons, num_input, input, witness, _) = c.transform().expect("transform failed");
        
        let time = Instant::now();
        //assert!(proof.verify(&proving_keys.ivk, &Vec::new()).is_ok());
        assert!(proof.verify(&proving_keys.ivk, &input).is_ok());
        let verification_time = time.elapsed().as_micros();
        println!("verification time: {:?}", verification_time);
        
        let bytes = proof.serialized_size(ark_serialize::Compress::Yes);
        println!("proof size: {:?}", bytes);
        
        // Append run conclusion to file

        write_measurements_to_csv_coord(path_transcript, proving_time, verification_time, bytes);
        


    } else {
        //Deserialize the proving keys

        // Worker code

        if local == 1 {
            worker_id = (rank as usize) - 1;
        } else {
            worker_id = worker_id - 1;
        }

        let mut proving_keys = {
            let mut buf = Vec::new();

            let mut file_name = key_file.clone();

            file_name.set_extension(worker_id.to_string());

            eprintln!("Worker {rank}: reading proving key from file {:?}", file_name);

            let mut f =
                File::open(&file_name).expect(&format!("couldn't open file {:?}", key_file));
            let _ = f.read_to_end(&mut buf);
            let buf_slice = buf.as_slice();

            let mut pk = DistributedRSSProverKey::<E>::deserialize_uncompressed_unchecked(buf_slice)
                .unwrap();


            pk
        };

        /*
        let current_num_threads = current_num_threads();
        println!(
            "Rayon num threads in worker {rank}: {}",
            current_num_threads
        );

        eprintln!("{:?}", proving_keys.r1cs.num_inputs);
        */

        let port = 8220;
        //let ip = 5 + rank as usize;
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut a: DenseMultilinearExtension<Fr254> = recv_ark(&mut stream).await.unwrap();
        let mut b: DenseMultilinearExtension<Fr254> = recv_ark(&mut stream).await.unwrap();

        let mut witness_0: DenseMultilinearExtension<Fr254> = recv_ark(&mut stream).await.unwrap();
        let mut witness_1: DenseMultilinearExtension<Fr254> = recv_ark(&mut stream).await.unwrap();

        
        
        

        let r1cs = proving_keys.r1cs.clone();
        let mut za_share_0 = vec![Fr254::zero(); a.evaluations.len()];
        let mut zb_share_0 = vec![Fr254::zero(); a.evaluations.len()];
        let mut zc_share_0 = vec![Fr254::zero(); a.evaluations.len()];

        let mut za_share_1 = vec![Fr254::zero(); b.evaluations.len()];
        let mut zb_share_1 = vec![Fr254::zero(); b.evaluations.len()];
        let mut zc_share_1 = vec![Fr254::zero(); b.evaluations.len()];

        for entry in &r1cs.A.M {
            za_share_0[entry.row] += a.evaluations[entry.col] * Fr254::from(entry.val);
            za_share_1[entry.row] += b.evaluations[entry.col] * Fr254::from(entry.val);
        }
        for entry in &r1cs.B.M {
            zb_share_0[entry.row] += a.evaluations[entry.col] * Fr254::from(entry.val);
            zb_share_1[entry.row] += b.evaluations[entry.col] * Fr254::from(entry.val);
        }
        for entry in &r1cs.C.M {
            zc_share_0[entry.row] += a.evaluations[entry.col] * Fr254::from(entry.val);
            zc_share_1[entry.row] += b.evaluations[entry.col] * Fr254::from(entry.val);
            
        }


        let mut za_share_0 = DenseMultilinearExtension::from_evaluations_vec(proving_keys.ipk.padded_num_var, za_share_0.clone());
        let mut zb_share_0 = DenseMultilinearExtension::from_evaluations_vec(proving_keys.ipk.padded_num_var, zb_share_0.clone());
        let mut zc_share_0 = DenseMultilinearExtension::from_evaluations_vec(proving_keys.ipk.padded_num_var, zc_share_0.clone());

        let mut za_share_1 = DenseMultilinearExtension::from_evaluations_vec(proving_keys.ipk.padded_num_var, za_share_1.clone());
        let mut zb_share_1 = DenseMultilinearExtension::from_evaluations_vec(proving_keys.ipk.padded_num_var, zb_share_1.clone());
        let mut zc_share_1 = DenseMultilinearExtension::from_evaluations_vec(proving_keys.ipk.padded_num_var, zc_share_1.clone());
        let party_num: usize = (rank - 1) as usize;
        let z_0 = RssPoly::<E>::new(party_num, a.clone(), b.clone());
        let za_0 = RssPoly::<E>::new(party_num, za_share_0.clone(), za_share_1.clone());
        let zb_0 = RssPoly::<E>::new(party_num, zb_share_0.clone(), zb_share_1.clone());
        let zc_0 = RssPoly::<E>::new(party_num, zc_share_0.clone(), zc_share_1.clone());
        let witness = RssPoly::<E>::new(party_num, witness_0.clone(), witness_1.clone());

        proving_keys.z = Some(z_0);
        proving_keys.za = Some(za_0);
        proving_keys.zb = Some(zb_0);
        proving_keys.zc = Some(zc_0);
        proving_keys.witness = Some(witness);

        // let worker_id = (rank as usize) - 1;

        let log_chunk_size = proving_keys.num_variables - log_num_workers_per_party;
        let start_eq = (1 << log_chunk_size) * (worker_id / 3);

        let pub_log_chunk_size = proving_keys.num_variables - log_num_public_workers;
     
        let pub_start_eq = (1 << pub_log_chunk_size) * worker_id;


        let active = (worker_id < (1 << log_num_public_workers));

    

        let mut seed_0 = Blake2s512Rng::setup();
        seed_0.feed(&proving_keys.seed_0.as_bytes());
        let mut seed_1 = Blake2s512Rng::setup();
        seed_1.feed(&proving_keys.seed_1.as_bytes());
        let mut random = SSRandom::<Blake2s512Rng>::new(seed_0, seed_1);

        let responses = "ready".to_string();
        send_responses(&mut log, rank, "worker ready", &root_process, &responses, 1);
        
        
        let (size1, size2) = dfs::mpc_snark::worker::RssPrivateProver::prove(
            &proving_keys,
            &mut log,
            "mpc_rss_worker_",
            size,
            rank,
            &root_process,
            log_num_workers_per_party,
            log_num_public_workers,
            start_eq,
            log_chunk_size,
            &mut random,
            active,
            //pub_start_eq,
            worker_id,
            //log_num_public_workers,
            pub_log_chunk_size,
        );
        send_size = send_size + size1;
        recv_size = recv_size + size2;

        let path_transcript = "app/measurments/meas.csv";

        write_measurements_to_csv_work(
            path_transcript,
            send_size,
            recv_size
        );

        
    }

    end_timer_buf!(log, very_start);

    println!(
        "Rank {rank} log: {}\nsend_msg_size: {}\nrecv_msg_size: {}\n",
        log.join(";"),
        send_size,
        recv_size
    );
}

#[cfg(feature = "parallel")]
fn execute_in_pool<T: Send>(f: impl FnOnce() -> T + Send, num_threads: usize) -> T {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();
    pool.install(f)
}
#[cfg(not(feature = "parallel"))]
fn execute_in_pool<T: Send>(f: impl FnOnce() -> T + Send, num_threads: usize) -> T {
    f()
}
#[cfg(not(feature = "parallel"))]
fn execute_in_pool_with_all_threads<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    f()
}
#[cfg(feature = "parallel")]
use rayon::current_num_threads;

#[cfg(not(feature = "parallel"))]
fn current_num_threads() -> usize {
    1
}

fn pool_and_chunk_size(num_threads: usize, num_requests: usize) -> (usize, usize) {
    let pool_size = if num_threads > num_requests {
        num_threads / num_requests
    } else {
        1
    };
    let chunk_size = if num_requests >= num_threads {
        num_requests / num_threads
    } else {
        num_threads
    };
    dbg!((pool_size, chunk_size))
}

fn compute_responses<'a, R, W, U, F>(
    requests: &'a [R],
    worker_states: impl IntoIterator<Item = W>,
    stage_fn: F,
) -> Vec<U>
where
    R: 'a + Send + Sync,
    W: Send + Sync,
    U: Send + Sync,
    F: Send + Sync + Fn(&'a R, W) -> U,
{
    let (pool_size, chunk_size) = pool_and_chunk_size(current_num_threads(), requests.len());
    thread::scope(|s| {
        let mut thread_results = Vec::new();
        let worker_state_chunks: Vec<Vec<_>> = worker_states
            .into_iter()
            .chunks(chunk_size)
            .into_iter()
            .map(|c| c.into_iter().collect())
            .collect();
        for (reqs, states) in requests.chunks(chunk_size).zip(worker_state_chunks) {
            let result = s.spawn(|_| {
                execute_in_pool(
                    || {
                        reqs.into_iter()
                            .zip(states)
                            .map(|(req, state)| stage_fn(req, state))
                            .collect::<Vec<_>>()
                    },
                    pool_size,
                )
            });
            thread_results.push(result);
        }
        thread_results
            .into_iter()
            .map(|t| t.join().unwrap())
            .flatten()
            .collect::<Vec<_>>()
    })
    .unwrap()
}

fn write_measurements_to_csv_work(
    filename: &str,
    send_bytes: usize,
    rec_byes: usize
) -> Result<(), Box<dyn std::error::Error>> {
    
    
    let file_exists = std::path::Path::new(filename).exists();
    
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)?;

    // Write header only if file is new
    if !file_exists {
        writeln!(file, "send_bytes,received_bytes")?;
    }

    // Write one row for each measurement pair
   
    writeln!(
        file,
        "{},{}",
        send_bytes, rec_byes
    )?;
    

    Ok(())
}


fn write_measurements_to_csv_coord(
    filename: &str,
    prove_time: u128,
    ver_times: u128,
    proof_size: usize
) -> Result<(), Box<dyn std::error::Error>> {
    
    
    let file_exists = std::path::Path::new(filename).exists();
    
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)?;

    // Write header only if file is new
    if !file_exists {
        writeln!(file, "proving_time,ver_time,proof_size")?;
    }

    // Write one row for each measurement pair
   
    writeln!(
        file,
        "{},{},{}",
        prove_time, ver_times, proof_size
    )?;
    

    Ok(())
}
