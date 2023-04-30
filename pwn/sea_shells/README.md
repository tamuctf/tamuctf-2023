# Sea Shells 

Author: `_mac_`

Sally sold some seashells by the seashore. Try to guess how many she sold, I bet you will never be able to!

## Dev Notes
Given files: `sea_shells.c` and `sea_shells``

**Setup:**
```
sudo make docker
sudo make run
```

By default `sea_shells` is running on port 9999

**Cleanup:**
```
sudo make clean
```

## Solution
First use the overflow provided by the scanf to overwrite num_sold, that way we know what it is.
Then get the leak by "guessing" the num_sold correctly, which is doable since you set the value.
Next, send shellcode to do a read, by putting the shellcode in a, b, c, and d variables, taking into account the math operating on those variables.
Then send nopslide+shellcode to the read, getting a shell.
Solve in `solve.py`

`gigem{cr34t1v3_5h3llc0d3_ftw}`
