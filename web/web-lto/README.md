# Web LTO

Author: `Addison`

I'm trying to create a more async-optimised version of the actix multipart example. That means switching over to tokio
File, reusing file handles, and so on. I think it's working great so far, and I don't think users can interact with each
other. Want to give it a try? I'm already using it to store my super-secret `flag.txt` file, and it holds up pretty well
to having repeated uploads (I'm testing at one upload every 10 seconds or so while I debug things!).

**Author note:** To prevent interaction between users, this challenge is stateless. You will not be able to download any
previously uploaded content. As a result, you may not observe files persisting between uploads and **bruteforcing is not
viable as a solution**.

## Dev Notes

Users will receive ./web-lto/* and ./index.html. Items relating to flag-uploader should not be provided to users.

In local testing, connect to port 8937.

## Solution

See [the solution crate](./solution). Use `cargo run | tar xv`, wait 12-15 seconds, then press `ctrl-d`.

The observation to be made is that the file is created, but is not ensured to be _freshly_ created. As a result, a
naming collision, provided that the file already exists, will reuse the file that already exists. When the remote
uploader interacts with the server and the file already exists, they overwrite the content of whatever we sent, then
copy out their content, then delete the file. But, if we hold open the file before they upload their content, then read
the file **even after they delete it**, the content will still be present in the file as the file will not be deleted
until after all file descriptors are closed, including ours.

The solution code implements this attack by creating the flag file, waiting (12-15 seconds), then closing the upload
stream without writing anything to the file. Since we won't truncate the file (as it is already open), when we seek back
to the beginning of the file for the copy, we read the file's content **even though the file is already deleted**. This
is also why we get a "No such file or directory" error upon completion of the exploit.

Flag: `gigem{l70_4_th3_weB_1s_aM4z1n6}`