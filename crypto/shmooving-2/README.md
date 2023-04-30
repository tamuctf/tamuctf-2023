# Shmooving 2

Author: `nhwn`

My AES-128 implementation was too slow, so I removed some non-essential logic. Good luck getting the flag!

## Solution
Looking at main.rs, we see that AES has been implemented in ECB mode except the `sub_bytes()` step has been commented out. Since the S-Box is the only part of AES that is non-linear, by removing that step, we now have a cipher that can be solved with some linear equations.  

Effectively, AES is now an affine cipher that can be represented with the equation: `c = Ap + K`
(If you want to read more about this go check out this crypto stack exchange post: https://crypto.stackexchange.com/questions/20228/consequences-of-aes-without-any-one-of-its-operations)

The tricky part is finding the A matrix. But I did this by commenting out the `add_round_key()` step and encrypting 128 inputs, each with only a single bit set to 1 and all others set to 0. The 128 outputs generated are the columns of the A matrix and which can then be used to create our needed matrix.

In `solve.py` we use `A.data` to build the A matrix (the file is `A` in byte form), solve for `K` using the known plaintext/ciphertext pair, and then decrypt the flag using the given ciphertext.

flag: 
`gigem{l1n34r_syst3ms_4r3_sc4ry}`
