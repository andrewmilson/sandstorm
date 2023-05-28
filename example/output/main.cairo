%builtins output

// Implicit arguments: addresses of the output and pedersen
// builtins.
func main{output_ptr}() {
    assert [output_ptr] = 9;

    // Manually update the output builtin pointer.
    let output_ptr = output_ptr + 1;

    // output_ptr and pedersen_ptr will be implicitly returned.
    return ();
}


