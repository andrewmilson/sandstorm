
<div align="center">

![Sandstorm](./darude.jpeg)

# sandstorm

**SHARP (almost 😉) compatible Cairo prover**

[![stability-experimental](https://img.shields.io/badge/stability-experimental-orange.svg)](https://github.com/mkenney/software-guides/blob/master/STABILITY-BADGES.md#experimental)

</div>

Sandstorm uses miniSTARK to generate (almost) SHARP compatible proofs for Cairo programs. The prover was built by reverse engineering StarkWare's Open-Source StarkEx Solidity verifier. So far Sandstorm uses exactly the same trace layout as SHARP ✅ but verifier challenges and contraint composition coefficients differ which prevent users from submitting Sandstorm's proofs to StarkWare's L1 smart contract. Fixing this is straighforward 👌.

# Decoding constraints

```bash
cargo run -r -F gpu,asm,parallel -- prove \
    --memory ./tmp/memory.bin \
    --program ./tmp/program.json \
    --trace ./tmp/trace.bin

source ~/cairo_venv/bin/activate
cairo-compile tmp/program.cairo --output tmp/program.json
cairo-run --program ./tmp/program.json --trace_file ./tmp/trace.bin --memory_file ./tmp/memory.bin
```

```
memory layout for constraint poly

column0: @ 0x1600

    // bit0
    - row0 @ 0x1600 - 0th
    - row1 @ 0x1620 - 1st

    // bit2
    - row2 @ 0x1640 - 2nd
    - row3 @ 0x1660 - 3rd

    // bit4
    - row4 @ 0x1680 - 4th
    - row5 @ 0x16a0 - 5th

    // bit3
    - row3 @ 0x1660 - 3rd
    - row4 @ 0x1680 - 4th


    // NOTE: op1_src? flag_op1_base_op0_0?
    // ==============================
    // cpu/decode/flag_op1_base_op0_0
    // // intermediate_value/cpu/decode/opcode_rc/bit_2
    // cpu__decode__opcode_rc__bit_2 @ 0x2be0 - 175th
    // // intermediate_value/cpu/decode/opcode_rc/bit_4
    // cpu__decode__opcode_rc__bit_4 @ 0x2c00 - 176th
    // // intermediate_value/cpu/decode/opcode_rc/bit_3
    // cpu__decode__opcode_rc__bit_3 @ 0x2c20 - 177th
    // ==============================
    // TODO: why this positioned in here? 
    // NOTE: may be because uses bits 2, 3, 4 (above)?


    // bit5
    - row3 @ 0x16a0 - 5th
    - row4 @ 0x16c0 - 6th

    // bit6
    - row3 @ 0x16c0 - 6th
    - row4 @ 0x16e0 - 7th

    // bit9
    - row9  @ 0x1720 - 9th
    - row10 @ 0x1740 - 10th


    // NOTE: op1_src? flag_res_op1_0?
    // TODO: WTF is bit9 used?
    // NOTE: looking at state transition pseudo code
    //       res is unused (0?) if pc_update == 4 aka bit 9
    // ==============================
    // // intermediate_value/cpu/decode/opcode_rc/bit_5 
    // cpu__decode__opcode_rc__bit_5 @ 0x2c60 - 179th
    // // intermediate_value/cpu/decode/opcode_rc/bit_6 
    // cpu__decode__opcode_rc__bit_6 @ 0x2c80 - 180th
    // // intermediate_value/cpu/decode/opcode_rc/bit_9 
    // cpu__decode__opcode_rc__bit_9 @ 0x2ca0 - 181st
    // ==============================


    // bit7
    - row7 @ 0x16e0 - 7th
    - row8 @ 0x1700 - 8th

    // bit8
    - row8 @ 0x1700 - 8th
    - row9 @ 0x1720 - 9th

    // flag_pc_update_regular_0
    // TODO: forcing pc update flag to be 1, 2, 4 not 0?
    // ==============================
    // // intermediate_value/cpu/decode/opcode_rc/bit_7
    // cpu__decode__opcode_rc__bit_7 @ 0x2ce0 - 183rd
    // // intermediate_value/cpu/decode/opcode_rc/bit_8
    // cpu__decode__opcode_rc__bit_8 @ 0x2d00 - 184th
    // // intermediate_value/cpu/decode/opcode_rc/bit_9
    // cpu__decode__opcode_rc__bit_9 @ 0x2ca0 - 181st
    // ==============================


    // bit12
    - row12 @ 0x1780 - 12th
    - row13 @ 0x17a0 - 13th

    // bit13
    - row13 @ 0x17a0 - 13th
    - row14 @ 0x17c0 - 14th


    // fp_update_regular_0 - 
    // TODO: WTF is update regular?
    // TODO: uses flags from opcode group? Only first two?
    // ==============================
    // // intermediate_value/cpu/decode/opcode_rc/bit_12
    // cpu__decode__opcode_rc__bit_12 - 0x2d40 - 186th
    // // intermediate_value/cpu/decode/opcode_rc/bit_13
    // cpu__decode__opcode_rc__bit_13 - 0x2d60 - 187th
    // ==============================



```