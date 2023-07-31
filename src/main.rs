use ark_ff::Field;
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use binary::AirPrivateInput;
use binary::AirPublicInput;
use binary::CompiledProgram;
use binary::Layout;
use binary::Memory;
use binary::RegisterStates;
use layouts::CairoWitness;
use ministark::hash::Sha256HashFn;
use ministark::stark::Stark;
use ministark::Proof;
use ministark::ProofOptions;
use ministark_gpu::fields::p18446744069414584321;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481;
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
    #[structopt(long, parse(from_os_str))]
    air_public_input: PathBuf,
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt, Debug)]
enum Command {
    Prove {
        #[structopt(long, parse(from_os_str))]
        output: PathBuf,
        #[structopt(long, parse(from_os_str))]
        air_private_input: PathBuf,
        // TODO: add validation to the proof options
        #[structopt(long, default_value = "65")]
        num_queries: u8,
        #[structopt(long, default_value = "2")]
        lde_blowup_factor: u8,
        #[structopt(long, default_value = "16")]
        proof_of_work_bits: u8,
        #[structopt(long, default_value = "8")]
        fri_folding_factor: u8,
        #[structopt(long, default_value = "16")]
        fri_max_remainder_coeffs: u8,
    },
    Verify {
        #[structopt(long, parse(from_os_str))]
        proof: PathBuf,
        #[structopt(long, default_value = "80")]
        required_security_bits: u8,
    },
}

fn main() {
    // read command-line args
    let SandstormOptions {
        program,
        air_public_input,
        command,
    } = SandstormOptions::from_args();
    let program_file = File::open(program).expect("could not open program file");
    let air_public_input_file =
        File::open(air_public_input).expect("could not open air public input");
    let program_json: serde_json::Value = serde_json::from_reader(program_file).unwrap();
    let prime: String = serde_json::from_value(program_json["prime"].clone()).unwrap();
    match prime.to_lowercase().as_str() {
        // Starkware's 252-bit Cairo field
        "0x800000000000011000000000000000000000000000000000000000000000001" => {
            use p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
            let program: CompiledProgram<Fp> = serde_json::from_value(program_json).unwrap();
            let air_public_input: AirPublicInput<Fp> =
                serde_json::from_reader(air_public_input_file).unwrap();
            match air_public_input.layout {
                Layout::Plain => {
                    type A = layouts::plain::AirConfig<Fp, Fp>;
                    type T = layouts::plain::ExecutionTrace<Fp, Fp>;
                    type C = claims::base::CairoClaim<Fp, A, T, Sha256HashFn>;
                    let claim = C::new(program, air_public_input);
                    execute_command(command, claim);
                }
                Layout::Starknet => {
                    use claims::sharp_to_solidity::StarknetSolidityClaim;
                    let claim = StarknetSolidityClaim::new(program, air_public_input);
                    execute_command(command, claim);
                }
                Layout::Recursive => {
                    type A = layouts::recursive::AirConfig;
                    type T = layouts::recursive::ExecutionTrace;
                    type C = claims::sharp_to_cairo::CairoClaim<A, T>;
                    let claim = C::new(program, air_public_input);
                    execute_command(command, claim);
                }
                _ => unimplemented!(),
            }
        }
        // Goldilocks
        "0xffffffff00000001" => {
            use p18446744069414584321::ark::Fp;
            use p18446744069414584321::ark::Fq3;
            let program: CompiledProgram<Fp> = serde_json::from_value(program_json).unwrap();
            let air_public_input: AirPublicInput<Fp> =
                serde_json::from_reader(air_public_input_file).unwrap();
            match air_public_input.layout {
                Layout::Plain => {
                    type A = layouts::plain::AirConfig<Fp, Fq3>;
                    type T = layouts::plain::ExecutionTrace<Fp, Fq3>;
                    type C = claims::base::CairoClaim<Fp, A, T, Sha256HashFn>;
                    let claim = C::new(program, air_public_input);
                    execute_command(command, claim);
                }
                Layout::Starknet => {
                    unimplemented!("'starknet' layout does not support Goldilocks field")
                }
                _ => unimplemented!(),
            }
        }
        prime => unimplemented!("prime field p={prime} is not supported yet"),
    }
}

fn execute_command<Fp: PrimeField, Claim: Stark<Fp = Fp, Witness = CairoWitness<Fp>>>(
    command: Command,
    claim: Claim,
) {
    match command {
        Command::Prove {
            output,
            air_private_input,
            num_queries,
            lde_blowup_factor,
            proof_of_work_bits,
            fri_folding_factor,
            fri_max_remainder_coeffs,
        } => {
            let options = ProofOptions::new(
                num_queries,
                lde_blowup_factor,
                proof_of_work_bits,
                fri_folding_factor,
                fri_max_remainder_coeffs,
            );
            prove(options, &air_private_input, &output, claim)
        }
        Command::Verify {
            proof,
            required_security_bits,
        } => verify(required_security_bits, &proof, claim),
    }
}

fn verify<Claim: Stark<Fp = impl Field>>(
    required_security_bits: u8,
    proof_path: &PathBuf,
    claim: Claim,
) {
    let proof_bytes = fs::read(proof_path).unwrap();
    let proof = Proof::<Claim>::deserialize_compressed(&*proof_bytes).unwrap();
    let now = Instant::now();
    claim.verify(proof, required_security_bits.into()).unwrap();
    println!("Proof verified in: {:?}", now.elapsed());
}

fn prove<Fp: PrimeField, Claim: Stark<Fp = Fp, Witness = CairoWitness<Fp>>>(
    options: ProofOptions,
    air_private_input_path: &PathBuf,
    output_path: &PathBuf,
    claim: Claim,
) {
    let air_private_input_file =
        File::open(air_private_input_path).expect("could not open the air private input file");
    let air_private_input: AirPrivateInput =
        serde_json::from_reader(air_private_input_file).unwrap();

    let trace_path = &air_private_input.trace_path;
    let trace_file = File::open(trace_path).expect("could not open trace file");
    let register_states = RegisterStates::from_reader(trace_file);

    let memory_path = &air_private_input.memory_path;
    let memory_file = File::open(memory_path).expect("could not open memory file");
    let memory = Memory::from_reader(memory_file);

    let witness = CairoWitness::new(air_private_input, register_states, memory);

    let now = Instant::now();
    let proof = pollster::block_on(claim.prove(options, witness)).unwrap();
    println!("Proof generated in: {:?}", now.elapsed());
    let security_level_bits = proof.security_level_bits();
    println!("Proof security (conjectured): {security_level_bits}bit");

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    println!("Proof size: {:?}KB", proof_bytes.len() / 1024);
    let mut f = File::create(output_path).unwrap();
    f.write_all(proof_bytes.as_slice()).unwrap();
    f.flush().unwrap();
    println!("Proof written to {}", output_path.as_path().display());
}
