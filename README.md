<div align="center">

![Sandstorm](./darude.jpeg)

# sandstorm

**Cairo prover powered by [miniSTARK](https://github.com/andrewmilson/ministark/)**

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/andrewmilson/sandstorm/blob/main/LICENSE)
[![stability-experimental](https://img.shields.io/badge/stability-experimental-orange.svg)](https://github.com/mkenney/software-guides/blob/master/STABILITY-BADGES.md#experimental)

</div>

Sandstorm uses [miniSTARK](https://github.com/andrewmilson/ministark/) to generate [SHARP](https://starknet.io/docs/sharp.html) compatible proofs for [Cairo](https://www.cairo-lang.org/) programs ([almost](#sandstorm-sharp-differences) 😉). The prover was built by reverse engineering [StarkWare's open source verifier](https://github.com/starkware-libs/starkex-contracts). Please get in touch with me at [andrew.j.milson@gmail.com](mailto:andrew.j.milson@gmail.com) if you want to fund the development of Cairo builtins, performance optimizations, full SHARP compatibility or proof recursion.

## Demo - proving Cairo programs

| ![Generating a proof](prover.gif) | ![Verifying a proof](verifier.gif) |
|:--:|:--:|
| *Generating the proof* | *Verifying the proof* 

In this demo, the prover has a Cairo program that appears to sum the values of an array. The prover runs the program with `cairo-run` to generate `trace.bin` (stores register values at each VM cycle) and `memory.bin` (stores memory address value pairs). The prover then runs `sandstorm prove` which builds a STARK execution trace and proof from `trace.bin`, `memory.bin` and the compiled program.


The verifier, supplied with this proof and the original code, can run `sandstorm verify` to assert the program was executed correctly without having to run the program themselves. This is a small program for demonstration purposes and it'd probably be faster for the verifier to run the program themselves. Sandstorm is capable of generating proofs for much larger programs, where proof verification would run orders of magnitude faster than running the program. To run this demo locally:

```bash
# 1. (optional) install Cairo and activate the venv
# https://www.cairo-lang.org/docs/quickstart.html
source ~/cairo_venv/bin/activate

# 2. (optional) compile and run the Cairo program
cairo-compile example/array-sum.cairo --proof_mode --output example/array-sum.json
cairo-run --program example/array-sum.json \
          --air_private_input example/air-private-input.json \
          --air_public_input example/air-public-input.json \
          --trace_file example/trace.bin \
          --memory_file example/memory.bin \
          --min_steps 128 \
          --proof_mode

# 3. generate the proof
# use `-F parallel,asm` if not using an M1 Mac
# make sure latest macOS is installed
cargo +nightly run -r -F gpu,parallel,asm -- \
    --program example/array-sum.json \
    prove --air-private-input example/air-private-input.json \
          --air-public-input example/air-public-input.json \
          --output example/array-sum.proof

# 4. verify the proof
cargo +nightly run -r -F parallel,asm -- \
    --program example/array-sum.json \
    verify --proof example/array-sum.proof
```

## Demo - SHARP compatible proof

```bash
# 1. (optional) install Cairo and activate the venv
# https://www.cairo-lang.org/docs/quickstart.html
source ~/cairo_venv/bin/activate

# 2. (optional) compile and run the Cairo program
cairo-compile example/pedersen/main.cairo --proof_mode --output example/pedersen/main_compiled.json
cairo-run --program example/pedersen/main_compiled.json \
          --air_private_input example/pedersen/air-private-input.json \
          --air_public_input example/pedersen/air-public-input.json \
          --trace_file example/pedersen/trace.bin \
          --memory_file example/pedersen/memory.bin \
          --layout starknet \
          --min_steps 128 \
          --proof_mode --print_info

# 3. generate the proof
cargo +nightly run -r -F parallel,asm -- \
    --program example/pedersen/main_compiled.json --layout starknet \
    --air-public-input example/pedersen/air-public-input.json \
    prove --air-private-input example/pedersen/air-private-input.json \
          --output example/array-sum.proof

# 4. verify the proof
cargo +nightly run -r -F parallel,asm -- \
    --program example/pedersen/main_compiled.json --layout starknet \
    --air-public-input example/pedersen/air-public-input.json \
    verify --proof example/array-sum.proof
```

## Proving Cairo programs with Goldilocks field

The goldilocks field is a magical 64-bit prime field that has very fast arithmetic. This field was discovered after StarkWare built their Solidity verifier for Cairo programs. As a result Cairo uses a much larger 252-bit prime field by default. Arithmetic in this 252-bit field is slow and it can be hard to practically utilize the storage provided by each field element. 

Sandstorm recently supported proving Cairo programs with the 64-bit Goldilocks field instead of StarkWare's default 252-bit field. On a M1 Max proof generation is 5x faster using the 64-bit Goldilocks field and only uses ~1/4 of the overall memory when compared against Cairo's default 252-bit field. To run and prove with Goldilocks field locally:

```bash
# 1. install Cairo and activate the venv
# https://www.cairo-lang.org/docs/quickstart.html
source ~/cairo_venv/bin/

# 2. compile the Cairo program with Goldilocks field
cairo-compile example/array-sum.cairo \
        --prime 18446744069414584321 \
        --output example/array-sum.json \
        --proof_mode

# 3. modify the Cairo runner to support Goldilocks
# there are a few overly protective asserts that need to be commented out to get 
# things working. The location of these files is based on where you installed Cairo.
# For me they were in `~/cairo_venv/lib/python3.9/site-packages/starkware/cairo/`.
# Remove or comment out the following asserts:
# - lang/vm/relocatable.py line 84 `assert value < 2 ** (8 * n_bytes - 1)`
# - lang/compiler/encode.py line 38 `assert prime > 2 ** (3 * OFFSET_BITS + 16)`

# 4. run the Cairo program
cairo-run --program example/array-sum.json \
          --trace_file example/trace.bin \
          --memory_file example/memory.bin \
          --min_steps 128 \
          --proof_mode

# 5. generate the proof
# use `-F parallel,asm` if not using an M1 Mac
cargo +nightly run -r -F gpu,parallel,asm -- \
    --program example/array-sum.json \
    prove --trace example/trace.bin \
          --memory example/memory.bin \
          --output example/array-sum.proof

# 6. verify the proof
cargo +nightly run -r -F parallel,asm -- \
    --program example/array-sum.json \
    verify --proof example/array-sum.proof
```

<h2 id="sandstorm-sharp-differences">Differences between Sandstorm and SHARP</h2>

Sandstorm implements a subset of the constraints and trace layout that's used by [StarkWare's STARK prover (SHARP)](https://starknet.io/docs/sharp.html). This subset contains all of all constraints outlined in the Cairo whitepaper (section 9.10) and characterizes the constraints required to prove correct execution of Cairo programs (no builtins... yet). Sandstorm has a different proof serialization format and calculates verifier randomness differently. These need to be the same to allow users to submit a Sandstorm generated proof to StarkWare's Ethereum STARK verifier (coming soon). 

## How Sandstorm works

Those curious about the inner workings of Sandstorm can read the comments in [air.rs](layouts/src/starknet/air.rs#36). The comments expect some understanding of how STARK proofs are generated - if you need some background on this then [Anatomy of a STARK (part 4)](https://aszepieniec.github.io/stark-anatomy/) by [Alan Szepieniec](https://twitter.com/aszepieniec) is a great resource. The pseudo code in section 4.5 of the [Cairo whitepaper](https://eprint.iacr.org/2021/1063.pdf) provides a nice high level overview of how some pieces fit together.


```
cairo-compile example/pedersen/main.cairo --proof_mode --output example/pedersen/main_compiled.json
cairo-run --program example/pedersen/main_compiled.json \
          --air_private_input example/pedersen/air-private-input.json \
          --air_public_input example/pedersen/air-public-input.json \
          --trace_file example/pedersen/trace.bin \
          --memory_file example/pedersen/memory.bin \
          --layout starknet \
          --min_steps 128 \
          --proof_mode

cargo +nightly run -r -F parallel,asm -- \
    --program example/pedersen/main_compiled.json --layout starknet \
    prove --air-private-input example/pedersen/air-private-input.json \
          --air-public-input example/pedersen/air-public-input.json \
          --output example/array-sum.proof

cargo +nightly run -r -F parallel,asm -- \
    --program example/pedersen/main_compiled.json --layout starknet \
    verify --proof example/array-sum.proof
```