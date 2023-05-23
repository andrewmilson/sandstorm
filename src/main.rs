use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use binary::CompiledProgram;
use binary::Memory;
use binary::RegisterStates;
use layouts::layout6;
use ministark::Proof;
use ministark::ProofOptions;
use ministark::Prover;
use ministark::StarkExtensionOf;
use ministark::Trace;
use ministark_gpu::fields::p18446744069414584321;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481;
use ministark_gpu::GpuFftField;
use sandstorm::prover::CairoProver;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "sandstorm", about = "cairo prover")]
struct SandstormOptions {
    #[structopt(long, parse(from_os_str))]
    program: PathBuf,
    #[structopt(subcommand)]
    command: SandstormCommand,
}

#[derive(StructOpt, Debug)]
enum SandstormCommand {
    Prove {
        #[structopt(long, parse(from_os_str))]
        trace: PathBuf,
        #[structopt(long, parse(from_os_str))]
        memory: PathBuf,
        #[structopt(long, parse(from_os_str))]
        output: PathBuf,
    },
    Verify {
        #[structopt(long, parse(from_os_str))]
        proof: PathBuf,
    },
}

fn main() {
    // TODO:
    // proof options for 95 bit security level
    let num_queries = 100;
    let lde_blowup_factor = 2;
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
    let SandstormOptions { program, command } = SandstormOptions::from_args();
    let program_file = File::open(program).expect("could not open program file");
    let program: CompiledProgram = serde_json::from_reader(program_file).unwrap();
    use SandstormCommand::*;
    match &*program.prime.to_lowercase() {
        // Starkware's 252-bit Cairo field
        "0x800000000000011000000000000000000000000000000000000000000000001" => {
            use p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
            match command {
                Prove {
                    trace,
                    memory,
                    output,
                } => prove::<Fp, Fp>(options, program, &trace, &memory, &output),
                Verify { proof } => verify::<Fp, Fp>(options, program, &proof),
            }
        }
        // Goldilocks
        "0xffffffff00000001" => {
            use p18446744069414584321::ark::Fp;
            use p18446744069414584321::ark::Fq3;
            match command {
                Prove {
                    trace,
                    memory,
                    output,
                } => prove::<Fp, Fq3>(options, program, &trace, &memory, &output),
                Verify { proof } => verify::<Fp, Fq3>(options, program, &proof),
            }
        }
        prime => unimplemented!("prime field p={prime} is not implemented yet"),
    }
}

fn verify<Fp: GpuFftField + PrimeField, Fq: StarkExtensionOf<Fp>>(
    options: ProofOptions,
    program: CompiledProgram,
    proof_path: &PathBuf,
) {
    let proof_bytes = fs::read(proof_path).unwrap();
    let proof: Proof<layout6::AirConfig<Fp, Fq>> =
        Proof::deserialize_compressed(proof_bytes.as_slice()).unwrap();
    let public_inputs = &proof.public_inputs;
    assert_eq!(program.get_public_memory(), public_inputs.public_memory);
    assert_eq!(options, proof.options);

    let now = Instant::now();
    proof.verify().unwrap();
    println!("Proof verified in: {:?}", now.elapsed());
}

fn prove<Fp: GpuFftField + PrimeField, Fq: StarkExtensionOf<Fp>>(
    options: ProofOptions,
    program: CompiledProgram,
    trace_path: &PathBuf,
    memory_path: &PathBuf,
    output_path: &PathBuf,
) {
    let now = Instant::now();

    let trace_file = File::open(trace_path).expect("could not open trace file");
    let register_states = RegisterStates::from_reader(trace_file);

    let memory_file = File::open(memory_path).expect("could not open memory file");
    let memory = Memory::from_reader(memory_file);

    let execution_trace = layout6::ExecutionTrace::<Fp, Fq>::new(memory, register_states, program);
    println!(
        "Generated execution trace (cols={}, rows={}) in {:.0?}",
        execution_trace.base_columns().num_cols(),
        execution_trace.base_columns().num_rows(),
        now.elapsed(),
    );

    let prover = CairoProver::new(options);
    let now = Instant::now();
    let proof = pollster::block_on(prover.generate_proof(execution_trace)).unwrap();
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
