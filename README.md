<div align="center">

![Sandstorm](./darude.jpeg)

# sandstorm

**SHARP compatible Cairo prover powered by [miniSTARK](https://github.com/andrewmilson/ministark/)**

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/andrewmilson/sandstorm/blob/main/LICENSE)
[![stability-experimental](https://img.shields.io/badge/stability-experimental-orange.svg)](https://github.com/mkenney/software-guides/blob/master/STABILITY-BADGES.md#experimental)
[![CI](https://github.com/andrewmilson/ministark/actions/workflows/ci.yml/badge.svg)](https://github.com/andrewmilson/ministark/actions/workflows/ci.yml)

</div>

Sandstorm uses [miniSTARK](https://github.com/andrewmilson/ministark/) to generate, almost 😉, [SHARP](https://starknet.io/docs/sharp.html) compatible proofs for Cairo programs. The prover was built by reverse engineering [StarkWare's Open-Source StarkEx verifier](https://github.com/starkware-libs/starkex-contracts). Please get in touch with me at [andrew.j.milson@gmail.com](mailto:andrew.j.milson@gmail.com) if you want to fund the development of:

* Reverse engineering the Cairo builtins
* Performance optimizations
* Proof reccursion


Sandstorm implements an exact subset of the constraints and trace layout that's used by [StarkWare's STARK prover (SHARP)](https://starknet.io/docs/sharp.html). This subset  is all the constraints outlined in the Cairo whitepaper (section 9.10) and is the minimal subset of constraints required to prove correct execution of Cairo programs (no builtins... yet). There are some other differences between Sandstorm and StarkWare's prover. For instance verifier challenges, proof serialization format and constraint composition coefficients all differ and would need to be the same to allow users from submitting a Sandstorm generated proof to StarkWare's Ethereum smart contract. 

Those curious about how Sandstorm works can read the comments in [air.rs](src/air.rs). The comments expect some understanding of how STARK proofs work - [Anatomy of a STARK](https://aszepieniec.github.io/stark-anatomy/) by [Alan Szepieniec](https://twitter.com/aszepieniec) is a great resource for this. Also the [Cairo whitepaper](https://eprint.iacr.org/2021/1063.pdf) section 4.5 pseudo code provides a nice high level overview of how some pieces fit together.

## Demo - proving Cairo programs

```bash
cargo run -r -F gpu,asm,parallel -- prove \
    --memory ./tmp/memory.bin \
    --program ./tmp/program.json \
    --trace ./tmp/trace.bin

source ~/cairo_venv/bin/activate
cairo-compile tmp/program.cairo --output tmp/program.json
cairo-run --program ./tmp/program.json --trace_file ./tmp/trace.bin --memory_file ./tmp/memory.bin
```

## How Sandstorm works