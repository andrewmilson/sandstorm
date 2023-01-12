cargo +nightly run -r -F asm -- \
    verify --program array-sum.json \
           --proof proof.local.bin