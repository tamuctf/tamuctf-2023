# MD5
MD5 jail?!?!?!?!

Author: `anomie`

## Dev Notes
Given `server.py`. Set up remote with `make run`

## Solution
Since the md5sum is shortened to only 3 bytes, we can just brute force the command. Here I'm using 
`cat flag.txt; echo '<number>'`
where I'm brute forcing the number until the hash matches. In this case, 8726574 works.

Flag: `gigem{3_bYt3_MD5_1s_Ju5t_pr00f_0f_W0rK}`

