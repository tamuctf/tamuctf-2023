# nope

Author: `anomie`

This program is pretty outta line, I can't seem to find the flag.

## Dev Notes

Only file given is binary `nope`.

## SOLUTION
Patched the binary so that instead of calling strcmp, it prints out the modified input string and the check string. Then I check if the strings are equal at the character I am brute-forcing. I added `{}_` to the start of the charset because there were multiple values that could transform to the same value for a given index for some reason. There's probably a better way to handle the false positives but my solve gets the flag so oh well. see `solve.py` for solution, all solve artifacts also included for your convenience.

Flag: `gigem{fUnky_1nlin3_4sm}`
