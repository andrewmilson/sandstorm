use sandstorm::ExecutionTrace;
use std::path::PathBuf;
use structopt::StructOpt;

mod air;
mod trace;

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
    let execution_trace = ExecutionTrace::from_file(program_path, trace_path, memory_path);

    // let trace = sandstorm::read_binary_trace(trace_path);
    // println!("YOOO: {:?}", trace);
}
