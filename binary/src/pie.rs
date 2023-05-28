//! position-independent executable (PIE)
use crate::utils::deserialize_big_uint;
use crate::utils::deserialize_vec_big_uint;
use alloc::vec::Vec;
use ruint::aliases::U256;
use serde::Deserialize;
use serde::Serialize;
use std::io::Read;
use std::io::Seek;

#[derive(Serialize, Deserialize, Debug)]
pub struct Segment {
    index: usize,
    size: usize,
}

#[derive(Deserialize, Debug)]
pub struct Program {
    #[serde(deserialize_with = "deserialize_big_uint")]
    prime: U256,
    #[serde(deserialize_with = "deserialize_vec_big_uint")]
    data: Vec<U256>,
}

#[derive(Deserialize, Debug)]
pub struct Metadata {
    extra_segments: Vec<Segment>,
    ret_fp_segment: Segment,
    program_segment: Segment,
    execution_segment: Segment,
    ret_pc_segment: Segment,
    program: Program,
}

pub struct Pie {
    metadata: Metadata,
}

impl Pie {
    pub fn from_reader(r: impl Read + Seek) {
        #[derive(Deserialize)]
        struct PieVersion {
            cairo_pie: String,
        }

        let mut zip = zip::ZipArchive::new(r).expect("not a valid Cairo PIE");

        // check PIE version
        let version_reader = zip.by_name("version.json").unwrap();
        let version: PieVersion = serde_json::from_reader(version_reader).unwrap();
        assert_eq!("1.1", version.cairo_pie);

        // read metadata
        let metadata_reader = zip.by_name("metadata.json").unwrap();
        let metadata: Metadata = serde_json::from_reader(metadata_reader).unwrap();
        println!("{:?}", metadata);
    }
}
