extern crate alloc;

use ark_ff::PrimeField;
use binary::AirPublicInput;
use binary::CairoAuxInput;
use binary::CompiledProgram;
use binary::MemoryEntry;
use layouts::CairoTrace;
use layouts::CairoWitness;
use ministark::air::AirConfig;
use ministark::Provable;
use ministark::Verifiable;
use ministark_gpu::GpuFftField;
use num_bigint::BigUint;
use sha2::Digest;
use std::marker::PhantomData;

pub struct CairoClaim<Fp: PrimeField, A: AirConfig<Fp = Fp>, T: CairoTrace<Fp = Fp>, D: Digest> {
    program: CompiledProgram,
    air_public_input: AirPublicInput,
    public_memory: Vec<MemoryEntry<Fp>>,
    _phantom: PhantomData<(A, T, D)>,
}

impl<Fp: GpuFftField + PrimeField, A: AirConfig<Fp = Fp>, T: CairoTrace<Fp = Fp>, D: Digest>
    CairoClaim<Fp, A, T, D>
{
    pub fn new(program: CompiledProgram, air_public_input: AirPublicInput) -> Self {
        let public_memory = air_public_input
            .public_memory
            .iter()
            .map(|e| MemoryEntry {
                address: e.address,
                value: Fp::from(BigUint::from(e.value)),
            })
            .collect::<Vec<MemoryEntry<Fp>>>();
        Self {
            program,
            air_public_input,
            public_memory,
            _phantom: PhantomData,
        }
    }

    pub fn program(&self) -> &CompiledProgram {
        &self.program
    }
}

impl<
        Fp: GpuFftField + PrimeField,
        A: AirConfig<Fp = Fp, PublicInputs = CairoAuxInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = A::Fq>,
        D: Digest,
    > Verifiable for CairoClaim<Fp, A, T, D>
{
    type Fp = A::Fp;
    type Fq = A::Fq;
    type AirConfig = A;
    type Digest = D;

    fn get_public_inputs(&self) -> CairoAuxInput<Fp> {
        CairoAuxInput {
            log_n_steps: self.air_public_input.n_steps.ilog2(),
            layout: self.air_public_input.layout,
            initial_ap: self.air_public_input.initial_ap().into(),
            initial_pc: self.air_public_input.initial_pc().into(),
            final_ap: self.air_public_input.final_ap().into(),
            final_pc: self.air_public_input.final_pc().into(),
            range_check_min: self.air_public_input.rc_min,
            range_check_max: self.air_public_input.rc_max,
            public_memory_padding: self
                .air_public_input
                .public_memory_padding()
                .try_into_felt_entry()
                .unwrap(),
            program_segment: self.air_public_input.memory_segments.program,
            execution_segment: self.air_public_input.memory_segments.execution,
            output_segment: self.air_public_input.memory_segments.output,
            pedersen_segment: self.air_public_input.memory_segments.pedersen,
            rc_segment: self.air_public_input.memory_segments.range_check,
            ecdsa_segment: self.air_public_input.memory_segments.ecdsa,
            bitwise_segment: self.air_public_input.memory_segments.bitwise,
            ec_op_segment: self.air_public_input.memory_segments.ec_op,
            poseidon_segment: self.air_public_input.memory_segments.poseidon,
            public_memory: self
                .air_public_input
                .public_memory
                .iter()
                .map(|&MemoryEntry { address, value }| MemoryEntry {
                    address,
                    value: Fp::from(BigUint::from(value)),
                })
                .collect(),
        }
    }
}

impl<
        Fp: GpuFftField + PrimeField,
        A: AirConfig<Fp = Fp, PublicInputs = CairoAuxInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = A::Fq>,
        D: Digest,
    > Provable for CairoClaim<Fp, A, T, D>
{
    type Witness = CairoWitness<Fp>;
    type Trace = T;

    fn generate_trace(&self, witness: CairoWitness<Fp>) -> T {
        T::new(self.program.clone(), self.air_public_input.clone(), witness)
    }
}
