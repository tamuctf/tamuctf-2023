# PRNG

Author: `anomie`

I know they say don't roll your own crypto, but secure RNG should be easy. How hard could it be?

## Dev Notes
Given file `server.py`

## Solution
This challenge implements a [linear congruential generator](https://en.wikipedia.org/wiki/Linear_congruential_generator) as a pseudo-random number generator. We're tasked with finding the next 10 outputs given the first 10, but we don't know the starting parameters. I googled "find LCG parameters" and eventually found https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lcg/parameter_recovery.py. Given the original parameters, we can easily compute the next 10 outputs. See `solve.py` for details.

Flag: `gigem{D0nt_r0ll_y0uR_oWn_RnG}`
