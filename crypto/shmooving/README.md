# Shmooving

Author: `nhwn`

I discovered a new optimization for my AES-128 implementation that makes it blazingly fast. I'll even let you test it out yourself!

## Solution
When `mix_columns()` is removed from AES, it removes any sort of diffusion between the ciphertext and the plaintext. This means that changing only 1 byte in the plaintext will result in a single byte changed of the ciphertext (though the location of the byte will be different than that of the plaintext). 

Fortunately, we can encrypt a block of every character since we are given the chance to encrypt a large message and see its output (and we know the possible input characters). From there, since we know the corresponding input, we can see which byte of the challenge ciphertext corresponds to a byte in the same location of a block in our encrypted ciphertext. When we find a match, we know the corresponding plaintext since the block was a single character. 

Repeat this for all bytes of the ciphertext to decrypt the challenge and get the flag! (Though we have to make sure to descramble the byte order as the final permutation of bytes isn't in the same order as the plaintext)

flag: `gigem{please_no_more_aes_challs}`
