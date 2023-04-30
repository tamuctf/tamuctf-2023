# Bank

Author: `nhwn`

I came up with this banking system that lets you deposit as much as you want. I'm not sure why, but my friend said it was a terrible idea...

## Dev Notes
Run `make extract` to get the zip archive.

## Solution
We're given 2 arbitrary writes (although the writes are additions of an arbitrary value rather than a simple assignment). Our goal is to overwrite the exit message to be "/bin/sh" and the GOT entry for `puts` to be `system`. Since our writes are additions, we don't need to worry about ASLR and can just directly compute the offset between `system` and `puts`. See `solve.py` for the full script.
