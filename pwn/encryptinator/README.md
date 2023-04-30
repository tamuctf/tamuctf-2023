# Encryptinator

Author: `_mac_`

I have made this super secure encryption engine. I'll encrypt any message and no one will ever be able to read it. Not even me!

## Dev Notes
Given files: `encryptinator.c` and `encryptinator`

**Setup:**
```
sudo make docker
sudo make run
```


By default `encryptinator` is running on port 9001

**Cleanup:**
```
sudo make clean
```

## Solution
The vulnerability is that the check on viewing the encrypted message only checks if the index is after, but not before, so we can provide negative values to leak information from the stack.

The idea is to encrypt, then when we "view the encrypted message," we can provide a negative value to leak the key used to encrypt, then we can use that to decrypt the flag.

See `solve.py` for details

Flag: `gigem{00ps_b4d_3rr0r_ch3ck1ng}`
