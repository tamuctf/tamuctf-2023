# Numbers :pensive:

Author: `nhwn`

It wouldn't be a real CTF without some contrived RSA challenge, right?

## Solution
How to find phi?
Acquire i samples of `(e_i, d_i)`.
Let `x_i = d_i * e_i`. Then for all `x_i`, `x_i = 1 (mod phi)` iff `x - 1 = phi * k` for some integer `k`.

We can (sometimes) determine phi because the gcd of all the `x_i - 1` should be phi, given enough samples.

Solve given in `solve.py`, though I don't think it is robust and may fail a few times.

Flag: `gigem{h4h4_numb3rs_ar3_s0_qu1rky}`
