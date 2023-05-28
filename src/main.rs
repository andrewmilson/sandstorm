use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use binary::AirPrivateInput;
use binary::AirPublicInput;
use binary::CompiledProgram;
use binary::Memory;
use binary::RegisterStates;
use layouts::CairoAirConfig;
use layouts::CairoExecutionTrace;
use ministark::Proof;
use ministark::ProofOptions;
use ministark::Prover;
use ministark_gpu::fields::p18446744069414584321;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481;
use sandstorm::prover::CairoProver;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;
use structopt::StructOpt;
use strum::EnumString;
use strum::EnumVariantNames;
use strum::VariantNames;

#[derive(StructOpt, Debug)]
#[structopt(name = "sandstorm", about = "cairo prover")]
struct SandstormOptions {
    #[structopt(long, parse(from_os_str))]
    program: PathBuf,
    #[structopt(
        long, 
        possible_values = Layout::VARIANTS, 
        case_insensitive = true, 
        default_value = "plain"
    )]
    layout: Layout,
    #[structopt(subcommand)]
    command: Command,
}

#[derive(EnumString, EnumVariantNames, Debug)]
#[strum(serialize_all = "kebab_case")]
enum Layout {
    Plain,
    Layout6,
}

#[derive(StructOpt, Debug)]
enum Command {
    Prove {
        #[structopt(long, parse(from_os_str))]
        output: PathBuf,
        #[structopt(long, parse(from_os_str))]
        air_private_input: PathBuf,
        #[structopt(long, parse(from_os_str))]
        air_public_input: PathBuf,
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
    let SandstormOptions {
        program,
        layout,
        command,
    } = SandstormOptions::from_args();
    let program_file = File::open(program).expect("could not open program file");
    let program: CompiledProgram = serde_json::from_reader(program_file).unwrap();
    match &*program.prime.to_lowercase() {
        // Starkware's 252-bit Cairo field
        "0x800000000000011000000000000000000000000000000000000000000000001" => {
            use p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
            match layout {
                Layout::Plain => {
                    type A = layouts::plain::AirConfig<Fp, Fp>;
                    type T = layouts::plain::ExecutionTrace<Fp, Fp>;
                    execute_command::<A, T>(command, options, program);
                },
                Layout::Layout6 => {
                    type A = layouts::layout6::AirConfig;
                    type T = layouts::layout6::ExecutionTrace;
                    execute_command::<A, T>(command, options, program);
                }
            }
        }
        // Goldilocks
        "0xffffffff00000001" => {
            use p18446744069414584321::ark::Fp;
            use p18446744069414584321::ark::Fq3;
            match layout {
                Layout::Plain => {
                    type A = layouts::plain::AirConfig<Fp, Fq3>;
                    type T = layouts::plain::ExecutionTrace<Fp, Fq3>;
                    execute_command::<A, T>(command, options, program);
                },
                Layout::Layout6 => unimplemented!("layout6 does not support Goldilocks field"),
            }
        }
        prime => unimplemented!("prime field p={prime} is not supported yet"),
    }
}

fn execute_command<A: CairoAirConfig, T: CairoExecutionTrace<Fp = A::Fp, Fq = A::Fq>>(command: Command, options: ProofOptions, program: CompiledProgram)where
A::Fp: PrimeField, {
    match command {
        Command::Prove {
            output,
            air_private_input,
            air_public_input,
        } => prove::<A, T>(options, program, &air_private_input, &air_public_input, &output),
        Command::Verify { proof } => verify::<A>(options, program, &proof),
    }
}

fn verify<A: CairoAirConfig>(options: ProofOptions, program: CompiledProgram, proof_path: &PathBuf)
where
    A::Fp: PrimeField,
{
    let proof_bytes = fs::read(proof_path).unwrap();
    let proof: Proof<A> = Proof::deserialize_compressed(proof_bytes.as_slice()).unwrap();
    let public_inputs = &proof.public_inputs;
    assert_eq!(program.get_public_memory(), public_inputs.public_memory);
    assert_eq!(options, proof.options);

    let now = Instant::now();
    proof.verify().unwrap();
    println!("Proof verified in: {:?}", now.elapsed());
}

fn prove<A: CairoAirConfig, T: CairoExecutionTrace<Fp = A::Fp, Fq = A::Fq>>(
    options: ProofOptions,
    program: CompiledProgram,
    air_private_input_path: &PathBuf,
    air_public_input_path: &PathBuf,
    output_path: &PathBuf,
) where
    A::Fp: PrimeField,
{
    let now = Instant::now();

    let air_private_input_file = File::open(air_private_input_path).expect("could not open the air private input file");
    let air_private_input: AirPrivateInput = serde_json::from_reader(air_private_input_file).unwrap();

    let trace_path = &air_private_input.trace_path;
    let trace_file = File::open(trace_path).expect("could not open trace file");
    let register_states = RegisterStates::from_reader(trace_file);

    let memory_path = &air_private_input.memory_path;
    let memory_file = File::open(memory_path).expect("could not open memory file {}");
    let memory = Memory::from_reader(memory_file);

    let air_public_input_file = File::open(air_public_input_path).expect("could not open the air public input file");
    let air_public_input: AirPublicInput = serde_json::from_reader(air_public_input_file).unwrap();

    let execution_trace = T::new(program, air_public_input, air_private_input, memory, register_states);
    println!(
        "Generated execution trace (cols={}, rows={}) in {:.0?}",
        execution_trace.base_columns().num_cols(),
        execution_trace.base_columns().num_rows(),
        now.elapsed(),
    );

    let prover = CairoProver::<A, T>::new(options);
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
