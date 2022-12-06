use ministark::ProofOptions;
use ministark::Prover;
use sandstorm::prover::CairoProver;
use sandstorm::trace::ExecutionTrace;
use std::path::PathBuf;
use std::time::Instant;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "sandstorm", about = "cairo prover")]
enum SandstormOptions {
    Prove {
        #[structopt(long, parse(from_os_str))]
        program: PathBuf,
        #[structopt(long, parse(from_os_str))]
        trace: PathBuf,
        #[structopt(long, parse(from_os_str))]
        memory: PathBuf,
        // TODO: proof options
    },
}

fn main() {
    // read command-line args
    match SandstormOptions::from_args() {
        SandstormOptions::Prove {
            program,
            trace,
            memory,
        } => prove(&program, &trace, &memory),
    }
}

fn prove(program_path: &PathBuf, trace_path: &PathBuf, memory_path: &PathBuf) {
    // TODO: unmodified from miniSTARK brainfuck example
    let num_queries = 10;
    let lde_blowup_factor = 4;
    let grinding_factor = 16;
    let fri_folding_factor = 8;
    let fri_max_remainder_size = 64;
    let options = ProofOptions::new(
        num_queries,
        lde_blowup_factor,
        grinding_factor,
        fri_folding_factor,
        fri_max_remainder_size,
    );

    let execution_trace = ExecutionTrace::from_file(program_path, trace_path, memory_path);
    let prover = CairoProver::new(options);
    let now = Instant::now();
    let proof = prover.generate_proof(execution_trace).unwrap();
    println!("Proof generated in: {:?}", now.elapsed());
    proof.verify().unwrap();
}
