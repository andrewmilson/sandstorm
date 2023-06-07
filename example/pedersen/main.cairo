%builtins output pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import (HashBuiltin, SignatureBuiltin, BitwiseBuiltin)
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.bitwise import bitwise_and
from starkware.cairo.common.signature import (
    verify_ecdsa_signature,
)

// Implicit arguments: addresses of the output and pedersen
// builtins.
func main{output_ptr, pedersen_ptr: HashBuiltin*, range_check_ptr, ecdsa_ptr: SignatureBuiltin*, bitwise_ptr: BitwiseBuiltin*}() {
    // The following line implicitly updates the pedersen_ptr
    // reference to pedersen_ptr + 3.
    let (res) = hash2{hash_ptr=pedersen_ptr}(1, 2);
    assert [output_ptr] = res;

    // Manually update the output builtin pointer.
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

    let (prez) = bitwise_and(12, 10);  // Binary (1100, 1010).
    assert prez = 8;  // Binary 1000.

    let (yoyo) = bitwise_and(
        1225578735933442828068102633747590437426782890965066746429241472187377583468,
        3568809569741913715045370357918125425757114920266578211811626257903121825123
    );
    assert yoyo = 1190020890442526208725573243584847930292605552660038159110459769316048045408;

    // output_ptr and pedersen_ptr will be implicitly returned.
    return ();
}