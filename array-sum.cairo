from starkware.cairo.common.alloc import alloc

func array_sum(arr: felt*, n) -> felt {
    if (n == 0) { 
        return 0;
    }
    return arr[0] + array_sum(arr=arr + 1, n=n - 1);
}

func main() {
    // allocate an array
    const ARRAY_SIZE = 3;
    let (ptr) = alloc();
    
    // populate array values
    assert [ptr] = 9;
    assert [ptr + 1] = 11;
    assert [ptr + 2] = 5;
    
    // Compute and check the sum
    let sum = array_sum(arr=ptr, n=ARRAY_SIZE);
    assert sum = 25;
    return ();
}