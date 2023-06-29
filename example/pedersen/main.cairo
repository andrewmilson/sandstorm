%builtins output pedersen range_check ecdsa bitwise ec_op poseidon

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin, BitwiseBuiltin, EcOpBuiltin, PoseidonBuiltin
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.ec_point import EcPoint
from starkware.cairo.common.ec import StarkCurve
from starkware.cairo.common.signature import check_ecdsa_signature
from starkware.cairo.common.builtin_poseidon.poseidon import poseidon_hash_single
// from starkware.cairo.common.signature import 
from starkware.cairo.common.bitwise import bitwise_and
from starkware.cairo.common.signature import (
    verify_ecdsa_signature,
)


// // Implicit arguments: addresses of the output and pedersen
// // builtins.
// func main{output_ptr, pedersen_ptr: HashBuiltin*, range_check_ptr, ecdsa_ptr: SignatureBuiltin*, bitwise_ptr: BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*}() {
//     alloc_locals;
//     // The following line implicitly updates the pedersen_ptr
//     // reference to pedersen_ptr + 3.
//     local pedersen_ptr: HashBuiltin* = pedersen_ptr;
//     let (res) = hash2{hash_ptr=pedersen_ptr}(1, 2);
//     assert [output_ptr] = res;

//     // Manually update the output builtin pointer.
//     let output_ptr = output_ptr + 1;

//     // assert [range_check_ptr] = 340282366920938463463374607431768211455;
//     // let range_check_ptr = range_check_ptr + 1;

//     assert [range_check_ptr] = 166156034813001157104264704933494816000;
//     let range_check_ptr = range_check_ptr + 1;

//     let user = 1628448741648245036800002906075225705100596136133912895015035902954123957052;
//     let amount = 4321;
//     let sig = (1225578735933442828068102633747590437426782890965066746429241472187377583468, 3568809569741913715045370357918125425757114920266578211811626257903121825123);
//     let (amount_hash) = hash2{hash_ptr=pedersen_ptr}(amount, 0);

//     verify_ecdsa_signature(
//         message=amount_hash,
//         public_key=user,
//         signature_r=sig[0],
//         signature_s=sig[1],
//     );

//     let (res) = check_ecdsa_signature(
//         message=amount_hash,
//         public_key=user,
//         signature_r=sig[0],
//         signature_s=sig[1],
//     );
//     assert res = 1;

//     // output_ptr and pedersen_ptr will be implicitly returned.
//     return ();
// }


// Implicit arguments: addresses of the output and pedersen
// builtins.
func main{output_ptr, pedersen_ptr: HashBuiltin*, range_check_ptr, ecdsa_ptr: SignatureBuiltin*, bitwise_ptr: BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*, poseidon_ptr: PoseidonBuiltin*}() {
    alloc_locals;
    // The following line implicitly updates the pedersen_ptr
    // reference to pedersen_ptr + 3.
    local pedersen_ptr: HashBuiltin* = pedersen_ptr;
    let (res) = hash2{hash_ptr=pedersen_ptr}(1, 2);
    // assert [output_ptr] = res;

    let myval = 0x666;
    assert [output_ptr] = myval;

    // Manually update the output builtin pointer.
    let output_ptr = output_ptr + 1;


    let myval = 0x987;
    assert [output_ptr] = myval;

    let output_ptr = output_ptr + 1;
    // assert [range_check_ptr] = 340282366920938463463374607431768211455;
    // let range_check_ptr = range_check_ptr + 1;

    assert [range_check_ptr] = 166156034813001157104264704933494816000;
    let range_check_ptr = range_check_ptr + 1;

    let user = 1628448741648245036800002906075225705100596136133912895015035902954123957052;
    let amount = 4321;
    let sig = (1225578735933442828068102633747590437426782890965066746429241472187377583468, 3568809569741913715045370357918125425757114920266578211811626257903121825123);
    let (amount_hash) = hash2{hash_ptr=pedersen_ptr}(amount, 0);

    verify_ecdsa_signature(
        message=amount_hash,
        public_key=user,
        signature_r=sig[0],
        signature_s=sig[1],
    );

    let (res) = check_ecdsa_signature(
        message=amount_hash,
        public_key=user,
        signature_r=sig[0],
        signature_s=sig[1],
    );
    assert res = 1;

    let (prez) = bitwise_and(12, 10);  // Binary (1100, 1010).
    assert prez = 8;  // Binary 1000.

    let (yoyo) = bitwise_and(
        1225578735933442828068102633747590437426782890965066746429241472187377583468,
        3568809569741913715045370357918125425757114920266578211811626257903121825123
    );
    assert yoyo = 1190020890442526208725573243584847930292605552660038159110459769316048045408;

    // let (zG: EcPoint) = ec_mul(m=3189, p=EcPoint(x=StarkCurve.GEN_X, y=StarkCurve.GEN_Y));
    let (simple_hash) = poseidon_hash_single(27318998);


    let (yo1) = bitwise_and(0, 0);
    assert yo1 = 0;
    let (yo2) = bitwise_and(0, 0);
    assert yo2 = 0;
    let (yo3) = bitwise_and(0, 0);
    assert yo3 = 0;
    let (yo4) = bitwise_and(0, 0);
    assert yo4 = 0;
    let (yo5) = bitwise_and(0, 0);
    assert yo5 = 0;

    // output_ptr and pedersen_ptr will be implicitly returned.
    return ();
}

// cairo-run --program bootloader_compiled.json \
//           --air_private_input ./air-private-input.json \
//           --air_public_input ./air-public-input.json \
//           --trace_file ./trace.bin \
//           --memory_file ./memory.bin \
//           --layout starknet \
//           --min_steps 128 \
//           --proof_mode --print_info