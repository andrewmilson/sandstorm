use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ministark::Proof;
use ministark::ProofOptions;
use ministark::Prover;
use ministark::Trace;
use sandstorm::air::CairoAir;
use sandstorm::binary::CompiledProgram;
use sandstorm::prover::CairoProver;
use sandstorm::trace::ExecutionTrace;
use std::fs;
use std::fs::File;
use std::io::Write;
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
        #[structopt(long, parse(from_os_str))]
        output: PathBuf,
    },
    Verify {
        #[structopt(long, parse(from_os_str))]
        program: PathBuf,
        #[structopt(long, parse(from_os_str))]
        proof: PathBuf,
    },
}

fn main() {
    // TODO:
    // proof options for 95 bit security level
    let num_queries = 20;
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

    // read command-line args
    match SandstormOptions::from_args() {
        SandstormOptions::Prove {
            program,
            trace,
            memory,
            output,
        } => prove(options, &program, &trace, &memory, &output),
        SandstormOptions::Verify { program, proof } => verify(options, &program, &proof),
    }
}

fn verify(options: ProofOptions, program_path: &PathBuf, proof_path: &PathBuf) {
    let program = CompiledProgram::from_file(program_path);
    let proof_bytes = fs::read(proof_path).unwrap();
    let proof: Proof<CairoAir> = Proof::deserialize_compressed(proof_bytes.as_slice()).unwrap();
    let public_inputs = &proof.public_inputs;
    assert_eq!(program.get_public_memory(), public_inputs.public_memory);
    assert_eq!(options, proof.options);

    let now = Instant::now();
    proof.verify().unwrap();
    println!("Proof verified in: {:?}", now.elapsed());
}

fn prove(
    options: ProofOptions,
    program_path: &PathBuf,
    trace_path: &PathBuf,
    memory_path: &PathBuf,
    output_path: &PathBuf,
) {
    let now = Instant::now();
    let execution_trace = ExecutionTrace::from_file(program_path, trace_path, memory_path);
    println!(
        "Generated execution trace (cols={}, rows={}) in {:.0?}",
        execution_trace.base_columns().num_cols(),
        execution_trace.base_columns().num_rows(),
        now.elapsed(),
    );

    let prover = CairoProver::new(options);
    let now = Instant::now();
    let proof = prover.generate_proof(execution_trace).unwrap();
    println!("Proof generated in: {:?}", now.elapsed());
    println!(
        "Proof security (conjectured): {}bit",
        proof.conjectured_security_level()
    );

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    println!("Proof size: {:?}KB", proof_bytes.len() / 1024);
    let mut f = File::create(output_path).unwrap();
    f.write_all(proof_bytes.as_slice()).unwrap();
    f.flush().unwrap();
    println!("Proof written to {}", output_path.as_path().display());
}
