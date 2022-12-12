<div align="center">

![Sandstorm](./darude.jpeg)

# sandstorm

**Cairo prover powered by [miniSTARK](https://github.com/andrewmilson/ministark/)**

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/andrewmilson/sandstorm/blob/main/LICENSE)
[![stability-experimental](https://img.shields.io/badge/stability-experimental-orange.svg)](https://github.com/mkenney/software-guides/blob/master/STABILITY-BADGES.md#experimental)

</div>

Sandstorm uses [miniSTARK](https://github.com/andrewmilson/ministark/) to generate, almost 😉, [SHARP](https://starknet.io/docs/sharp.html) compatible proofs for Cairo programs. The prover was built by reverse engineering [StarkWare's Open-Source StarkEx verifier](https://github.com/starkware-libs/starkex-contracts). Please get in touch with me at [andrew.j.milson@gmail.com](mailto:andrew.j.milson@gmail.com) if you want to fund the development of Cairo builtins, performance optimizations, full SHARP compatibility or proof recursion.

## Demo - proving Cairo programs

| ![Generating a proof](https://raw.githubusercontent.com/andrewmilson/ministark/main/prover.gif) | ![Verifying a proof](https://raw.githubusercontent.com/andrewmilson/ministark/main/verifier.gif) |
|:--:|:--:|
| *Generating the proof* | *Verifying the proof* 

In this example the prover generates a proof that proves they know the values of an array sum to 25. The verifier uses the proof and Cairo source code to verify this fact without executing the Cairo program at all. To run this demo locally:

```bash
# 1. (optional) Install Cairo and activate the venv
# https://www.cairo-lang.org/docs/quickstart.html
source ~/cairo_venv/bin/activate

# 2. (optional) Compile and run the Cairo program
cairo-compile array-sum.cairo --output program.json
cairo-run --program program.json \
          --trace_file trace.bin \
          --memory_file memory.bin

# 3. generate the proof
cargo +nightly run -r -F parallel,asm -- \
    prove --program program.json \
          --trace trace.bin \
          --memory memory.bin \
          --output array-sum.proof

# 4. verify the proof
cargo +nightly run -r -F parallel,asm -- \
    verify --program program.json \
           --proof array-sum.proof

# 5. (optional) GPU proof generation on M1 Mac 
# M1 Mac users can install miniSTARK locally
# and generate Cairo proofs on the GPU. This
# requires Xcode but is much faster
# https://github.com/andrewmilson/ministark
# `cargo +nightly run -r -F gpu,parallel,asm ...`
```

## Differences between Sandstorm and SHARP

Sandstorm implements an exact subset of the constraints and trace layout that's used by [StarkWare's STARK prover (SHARP)](https://starknet.io/docs/sharp.html). This subset is the set of all constraints outlined in the Cairo whitepaper (section 9.10) and is the set of constraints required to prove correct execution of Cairo programs (no builtins... yet). There are some other differences between Sandstorm and SHARP. Sandstorm has a different proof serialization format and calculates verifier randomness differently. These need to be the same to allow users to submit a Sandstorm generated proof to StarkWare's Ethereum STARK verifier. 

## How Sandstorm works

Those curious about how Sandstorm works can read the comments in [air.rs](src/air.rs#L115). The comments expect some understanding of how STARK proofs work - [Anatomy of a STARK](https://aszepieniec.github.io/stark-anatomy/) by [Alan Szepieniec](https://twitter.com/aszepieniec) is a great resource for this. Also the pseudo code in section 4.5 of the [Cairo whitepaper](https://eprint.iacr.org/2021/1063.pdf) provides a nice high level overview of how some pieces fit together.