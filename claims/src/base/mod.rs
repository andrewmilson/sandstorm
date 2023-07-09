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

    pub fn auxiliary_input(&self) -> CairoAuxInput<Fp> {
        // assert_eq!(self.initial_registers.ap, self.initial_registers.fp);
        // assert_eq!(self.initial_registers.ap, self.final_registers.fp);
        let public_input = &self.air_public_input;
        let memory_segments = &public_input.memory_segments;
        let initial_pc = memory_segments.program.begin_addr.into();
        let final_pc = memory_segments.program.stop_ptr.into();
        let initial_ap = memory_segments.execution.begin_addr.into();
        let final_ap = memory_segments.execution.stop_ptr.into();
        CairoAuxInput {
            initial_ap,
            initial_pc,
            final_ap,
            final_pc,
            public_memory: self.public_memory.clone(),
            log_n_steps: public_input.n_steps.ilog2(),
            layout: public_input.layout,
            range_check_min: public_input.rc_min,
            range_check_max: public_input.rc_max,
            public_memory_padding: self.program.get_public_memory_padding(),
            program_segment: memory_segments.program,
            execution_segment: memory_segments.execution,
            output_segment: memory_segments.output,
            pedersen_segment: memory_segments.pedersen,
            rc_segment: memory_segments.range_check,
            ecdsa_segment: memory_segments.ecdsa,
            bitwise_segment: memory_segments.bitwise,
            ec_op_segment: memory_segments.ec_op,
            poseidon_segment: memory_segments.poseidon,
        }
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
        self.auxiliary_input()
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
        let trace = T::new(self.program.clone(), self.air_public_input.clone(), witness);
        assert_eq!(trace.auxiliary_input(), self.auxiliary_input());
        trace
    }
}
