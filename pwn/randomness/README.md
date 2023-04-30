# Randomness

Author: `anomie`

I made this program to test how srand and rand work, but it keeps segfaulting. I don't read compiler warnings so I can't figure out why it's broken.

## Dev Notes
Run server with `make run`, default port is 6970. Competitors are given source (`randomness.c`) and binary (`randomness`). Get binary with `make extract`

## Solution
Let's look at `bar()` from the source:
```c
unsigned long a;

puts("Enter your guess:");
scanf("%lu", a);
```
Here, `scanf()` requires a pointer to a destination, but the value of the destination is passed instead. Furthermore, since `a` is uninitialized, it contains the value loaded in as the seed in `foo()`. Thus, we can write an arbitrary integer anywhere. Since `main()` calls `puts()` after the write, we can overwrite the GOT entry for `puts()` to be `win()`. See `solve.py` for details.
