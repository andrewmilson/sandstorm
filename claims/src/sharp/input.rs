use binary::{AirPublicInput, Layout};
use digest::Digest;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use num_bigint::BigUint;
use ruint::{aliases::U256, uint};

use crate::sharp::utils::hash_elements;

pub struct CairoAuxInput<'a>(pub &'a AirPublicInput<Fp>);

impl<'a> CairoAuxInput<'a> {
    fn base_values(&self) -> Vec<U256> {
        const OFFSET_LOG_N_STEPS: usize = 0;
        const OFFSET_RC_MIN: usize = 1;
        const OFFSET_RC_MAX: usize = 2;
        const OFFSET_LAYOUT_CODE: usize = 3;
        const OFFSET_PROGRAM_BEGIN_ADDR: usize = 4;
        const OFFSET_PROGRAM_STOP_PTR: usize = 5;
        const OFFSET_EXECUTION_BEGIN_ADDR: usize = 6;
        const OFFSET_EXECUTION_STOP_PTR: usize = 7;
        const OFFSET_OUTPUT_BEGIN_ADDR: usize = 8;
        const OFFSET_OUTPUT_STOP_PTR: usize = 9;
        const OFFSET_PEDERSEN_BEGIN_ADDR: usize = 10;
        const OFFSET_PEDERSEN_STOP_PTR: usize = 11;
        const OFFSET_RANGE_CHECK_BEGIN_ADDR: usize = 12;
        const OFFSET_RANGE_CHECK_STOP_PTR: usize = 13;

        let segments = self.0.memory_segments;

        const NUM_VALS: usize = OFFSET_RANGE_CHECK_STOP_PTR + 1;
        let mut vals = [None; NUM_VALS];
        vals[OFFSET_LOG_N_STEPS] = Some(U256::from(self.0.n_steps.ilog2()));
        vals[OFFSET_RC_MIN] = Some(U256::from(self.0.rc_min));
        vals[OFFSET_RC_MAX] = Some(U256::from(self.0.rc_max));
        vals[OFFSET_LAYOUT_CODE] = Some(U256::from(self.0.layout.sharp_code()));
        vals[OFFSET_PROGRAM_BEGIN_ADDR] = Some(U256::from(segments.program.begin_addr));
        vals[OFFSET_PROGRAM_STOP_PTR] = Some(U256::from(segments.program.stop_ptr));
        vals[OFFSET_EXECUTION_BEGIN_ADDR] = Some(U256::from(segments.execution.begin_addr));
        vals[OFFSET_EXECUTION_STOP_PTR] = Some(U256::from(segments.execution.stop_ptr));
        vals[OFFSET_OUTPUT_BEGIN_ADDR] = segments.output.map(|s| U256::from(s.begin_addr));
        vals[OFFSET_OUTPUT_STOP_PTR] = segments.output.map(|s| U256::from(s.stop_ptr));
        vals[OFFSET_PEDERSEN_BEGIN_ADDR] = segments.pedersen.map(|s| U256::from(s.begin_addr));
        vals[OFFSET_PEDERSEN_STOP_PTR] = segments.pedersen.map(|s| U256::from(s.stop_ptr));
        vals[OFFSET_RANGE_CHECK_BEGIN_ADDR] =
            segments.range_check.map(|s| U256::from(s.begin_addr));
        vals[OFFSET_RANGE_CHECK_STOP_PTR] = segments.range_check.map(|s| U256::from(s.stop_ptr));
        vals.map(Option::unwrap).to_vec()
    }

    fn layout_specific_values(&self) -> Vec<U256> {
        let segments = self.0.memory_segments;
        let public_memory_padding = self.0.public_memory_padding();

        match self.0.layout {
            Layout::Starknet => {
                const OFFSET_ECDSA_BEGIN_ADDR: usize = 0;
                const OFFSET_ECDSA_STOP_PTR: usize = 1;
                const OFFSET_BITWISE_BEGIN_ADDR: usize = 2;
                const OFFSET_BITWISE_STOP_ADDR: usize = 3;
                const OFFSET_EC_OP_BEGIN_ADDR: usize = 4;
                const OFFSET_EC_OP_STOP_ADDR: usize = 5;
                const OFFSET_POSEIDON_BEGIN_ADDR: usize = 6;
                const OFFSET_POSEIDON_STOP_PTR: usize = 7;
                const OFFSET_PUBLIC_MEMORY_PADDING_ADDR: usize = 8;
                const OFFSET_PUBLIC_MEMORY_PADDING_VALUE: usize = 9;
                const OFFSET_N_PUBLIC_MEMORY_PAGES: usize = 10;

                const NUM_VALS: usize = OFFSET_N_PUBLIC_MEMORY_PAGES + 1;
                let mut vals = [None; NUM_VALS];
                vals[OFFSET_ECDSA_BEGIN_ADDR] = segments.ecdsa.map(|s| U256::from(s.begin_addr));
                vals[OFFSET_ECDSA_STOP_PTR] = segments.ecdsa.map(|s| U256::from(s.stop_ptr));
                vals[OFFSET_BITWISE_BEGIN_ADDR] =
                    segments.bitwise.map(|s| U256::from(s.begin_addr));
                vals[OFFSET_BITWISE_STOP_ADDR] = segments.bitwise.map(|s| U256::from(s.stop_ptr));
                vals[OFFSET_EC_OP_BEGIN_ADDR] = segments.ec_op.map(|s| U256::from(s.begin_addr));
                vals[OFFSET_EC_OP_STOP_ADDR] = segments.ec_op.map(|s| U256::from(s.stop_ptr));
                vals[OFFSET_POSEIDON_BEGIN_ADDR] =
                    segments.poseidon.map(|s| U256::from(s.begin_addr));
                vals[OFFSET_POSEIDON_STOP_PTR] = segments.poseidon.map(|s| U256::from(s.stop_ptr));
                vals[OFFSET_PUBLIC_MEMORY_PADDING_ADDR] =
                    Some(U256::from(public_memory_padding.address));
                vals[OFFSET_PUBLIC_MEMORY_PADDING_VALUE] =
                    Some(U256::from::<BigUint>(public_memory_padding.value.into()));
                // Only 1 memory page currently for the main memory page
                // TODO: support more memory pages
                vals[OFFSET_N_PUBLIC_MEMORY_PAGES] = Some(uint!(1_U256));
                vals.map(Option::unwrap).to_vec()
            }
            Layout::Recursive => {
                const OFFSET_BITWISE_BEGIN_ADDR: usize = 0;
                const OFFSET_BITWISE_STOP_ADDR: usize = 1;
                const OFFSET_PUBLIC_MEMORY_PADDING_ADDR: usize = 2;
                const OFFSET_PUBLIC_MEMORY_PADDING_VALUE: usize = 3;
                const OFFSET_N_PUBLIC_MEMORY_PAGES: usize = 4;

                const NUM_VALS: usize = OFFSET_N_PUBLIC_MEMORY_PAGES + 1;
                let mut vals = [None; NUM_VALS];

                vals[OFFSET_BITWISE_BEGIN_ADDR] =
                    segments.bitwise.map(|s| U256::from(s.begin_addr));
                vals[OFFSET_BITWISE_STOP_ADDR] = segments.bitwise.map(|s| U256::from(s.stop_ptr));
                vals[OFFSET_PUBLIC_MEMORY_PADDING_ADDR] =
                    Some(U256::from(public_memory_padding.address));
                vals[OFFSET_PUBLIC_MEMORY_PADDING_VALUE] =
                    Some(U256::from::<BigUint>(public_memory_padding.value.into()));
                // Only 1 memory page currently for the main memory page
                // TODO: support more memory pages
                vals[OFFSET_N_PUBLIC_MEMORY_PAGES] = Some(uint!(1_U256));
                vals.map(Option::unwrap).to_vec()
            }
            _ => unimplemented!(),
        }
    }

    fn memory_page_values<D: Digest>(&self) -> Vec<U256> {
        // The public memory consists of individual memory pages.
        // The first page is for main memory.
        // For each page:
        // * First address in the page (this field is not included for the first page).
        // * Page size. (number of memory pairs)
        // * Page hash (hash of memory pairs)
        // TODO: support other memory pages
        const _PAGE_INFO_ADDRESS_OFFSET: usize = 0;
        const _PAGE_INFO_SIZE_OFFSET: usize = 1;
        const _PAGE_INFO_HASH_OFFSET: usize = 2;

        // Hash the address value pairs of the main memory page
        let main_page_hash: [u8; 32] = {
            let pairs = self
                .0
                .public_memory
                .iter()
                .flat_map(|e| [e.address.into(), e.value])
                .collect::<Vec<Fp>>();

            let mut hasher = D::new();
            hash_elements(&mut hasher, &pairs);
            (*hasher.finalize()).try_into().unwrap()
        };

        // NOTE: no address main memory page because It's implicitly "1".
        let mut main_page = [None; 2];
        main_page[0] = Some(U256::from(self.0.public_memory.len()));
        main_page[1] = Some(U256::try_from_be_slice(&main_page_hash).unwrap());

        main_page.map(Option::unwrap).to_vec()
    }

    pub fn public_input_elements<D: Digest>(&self) -> Vec<U256> {
        [
            self.base_values(),
            self.layout_specific_values(),
            self.memory_page_values::<D>(),
        ]
        .concat()
    }
}
