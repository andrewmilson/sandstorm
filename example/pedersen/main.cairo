%builtins output pedersen

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash import hash2

// Implicit arguments: addresses of the output and pedersen
// builtins.
func main{output_ptr, pedersen_ptr: HashBuiltin*}() {
    // The following line implicitly updates the pedersen_ptr
    // reference to pedersen_ptr + 3.
    let (res) = hash2{hash_ptr=pedersen_ptr}(1, 2);
    assert [output_ptr] = res;

    // Manually update the output builtin pointer.
    let output_ptr = output_ptr + 1;

    // output_ptr and pedersen_ptr will be implicitly returned.
    return ();
}