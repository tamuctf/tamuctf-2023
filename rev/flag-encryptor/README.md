# Flag Encryptor

Author: `anomie`

This program appears to look for a file `flag.png` and encrypts it.

## Dev notes
Given files are `flag-encryptor` and `flag.png`. Acquire these files by running `make dist`

To initialize this so that `make dist` Just Works:tm:, run the following:
```
git submodule init
git submodule update
```

## Solution
Looking at the binary statically (stripped :pensive:), we can find the entry point in Ghidra by looking for references to `__libc_start_main`; the caller will pass the address of `main` as the first argument. `main` immediately calls `mprotect` with all protections enabled (`PROT_READ | PROT_WRITE | PROT_EXEC`), so the subsequent functions probably unpack code. After doing some basic exploration, we have the following:
```c
void decrypt_memory(byte *ptr) {
    ulong i;

    for (i = 0; i < 0x1c2; i = i + 1) {
        ptr[i] = ptr[i] ^ XOR_KEY[(uint)i & 0xf];
    }
    return;
}

void main(void) {
    mprotect((void *)0x2000,0x8a3,7);
    decrypt_memory((byte *)encrypted_fun);
    encrypted_fun();
    return;
}
```

To take a closer look at the encrypted payload, let's look at this with dynamic analysis. Since PIE is on, we'll need to set breakpoints in `gdb` by first running the binary with `starti`, then breaking on the actual addresses with `b $_base() + <addr>`. After breaking just before the jump into the decrypted payload, we can dump the memory for further examination:
```
dump memory decrypted 0x005555555566e1 (0x005555555566e1 + 0x1c2)
```

To look at the disassembly, I googled https://stackoverflow.com/questions/14290879/disassembling-a-flat-binary-file-using-objdump because I never remember the flags.
```
objdump -D -Mintel,x86-64 -b binary -m i386 decrypted > out.s
```

However, looking at the disassembly is really terrible, so we'll load the decrypted instructions back into Ghidra to decompile it. To do this:

1. Get the hexadecimal values of the decrypted instructions into a single line, and copy it to your clipboard:
```
> xxd -p -c 100000 decrypted
554889e54881ece0000000488d3511090000488d3d0e090000e891e9ffff488945f048837df0007511488d3d00090000e81ae9ffffe986010000488b45f0ba02000000be000000004889c7e83fe9ffff83f8ff7511488d3dee080000e85ee9ffffe95a010000488b45f04889c7e80de9ffff488945e848837de8ff7511488d3dd2080000e836e9ffffe932010000488b45e8489948c1ea3c4801d083e00f4829d0ba100000004829c24889d0480145e8488b45e84889c6bf01000000e8aee8ffff488945e048837de0007511488d3d89080000e877e8ffffe9e3000000488b45f0ba00000000be000000004889c7e89ce8ffff83f8ff7511488d3d6b080000e8bbe8ffffe9b7000000488b75e8488b55f0488b45e04889d1ba010000004889c7e83ae8ffff488d8520ffffff488d357c2800004889c7e8e3ecffff48c745f800000000eb22488b55f8488b45e04801c2488d8520ffffff4889d64889c7e871fbffff488345f810488b45f8483b45e87cd4488b45f0ba00000000be000000004889c7e808e8ffff83f8ff750e488d3de4070000e827e8ffffeb26488b75e8488b55f0488b45e04889d1ba010000004889c7e829e8ffffbf00000000e80fe8ffffc9c3
```
2. Go to "Window", then select "Script Manager".
3. Highlight the first byte (click and drag your cursor over the first 2 nibbles) within the listing that you want to start overwriting from.
4. Switch over to the "Script Manager" window, then search for "EditBytesScript.java".
5. Run the script by double-clicking the entry.
6. Paste your clipboard when it prompts you with "Replace bytes at cursor with"; it will automatically separate the bytes within your input with whitespace.
7. Click "OK".

Unfortunately, when I did this, there were several errors in the disassembly (indicated by red "X" marks in the listing). To fix this, repeat the following for each error:

1. Highlight the bytes to fix (refer to your output from `objdump` to determine the starting and ending bytes).
2. Type "c" to clear the current disassembly for the bytes.
3. Type "d" to disassemble the bytes again.

After much laboring, here's the decompilation for the encrypted function:

```c
void encrypted_fun(void) {
    int iVar1;
    undefined auStack_e8 [192];
    void *pvStack_28;
    size_t sStack_20;
    FILE *pFStack_18;
    long lStack_10;

    pFStack_18 = fopen("flag.png","rb+");
    if (pFStack_18 == (FILE *)0x0) {
        puts("No flag.png to encrypt :(");
    }
    else {
        iVar1 = fseek(pFStack_18,0,2);
        if (iVar1 == -1) {
            perror("first fseek");
        }
        else {
            sStack_20 = ftell(pFStack_18);
            if (sStack_20 == -1) {
                perror("ftell");
            }
            else {
                sStack_20 = sStack_20 + (0x10 - (long)sStack_20 % 0x10);
                pvStack_28 = calloc(1,sStack_20);
                if (pvStack_28 == (void *)0x0) {
                    puts("calloc failed");
                }
                else {
                    iVar1 = fseek(pFStack_18,0,0);
                    if (iVar1 == -1) {
                        perror("second fseek");
                    }
                    else {
                        fread(pvStack_28,sStack_20,1,pFStack_18);
                        FUN_000014ff(auStack_e8,XOR_KEY);
                        for (lStack_10 = 0; lStack_10 < (long)sStack_20; lStack_10 = lStack_10 + 0x10) {
                            FUN_000023b4(auStack_e8,lStack_10 + (long)pvStack_28);
                        }
                        iVar1 = fseek(pFStack_18,0,0);
                        if (iVar1 != -1) {
                            fwrite(pvStack_28,sStack_20,1,pFStack_18);
                            /* WARNING: Subroutine does not return */
                            exit(0);
                        }
                        perror("third fseek");
                    }
                }
            }
        }
    }
    return;
}
```

This looks much nicer! This reads `flag.png` from the current working directory, then presumably encrypts the data section of the PNG. After exploring more of the functions, it's evident that the encryption algorithm is AES-128-ECB, where the encryption key is the XOR key used to decrypt the second stage. The biggest indicators are the lookup table for the substitution box (the first few bytes start with 0x63, 0x7C, 0x77, 0x7B, etc.) and the operation on chunks of 16 bytes at a time.
```
SBOX

00003080 63              db         63h
00003081 7c              db         7Ch
00003082 77              db         77h
00003083 7b              db         7Bh
...
```
```c
void sbox(uint8_t *param_1) {
    byte j;
    byte i;

    for (i = 0; i < 4; i = i + 1) {
        for (j = 0; j < 4; j = j + 1) {
            param_1[(long)(int)(uint)i + (long)(int)(uint)j * 4] =
                (&SBOX)[(int)(uint)param_1[(long)(int)(uint)i + (long)(int)(uint)j * 4]];
        }
    }
    return;
}
```

Now, we just need to decrypt the data within the image. To extract the key bytes from Ghidra, we can highlight the bytes of the key within the listing, click "Copy Special...", then select "Python Byte String". For decryption, we can use [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html). The magic bytes are corrupted, so we'll start from the beginning of the file, then iterate in chunks of 16 bytes (we won't mess with any remaining bytes).
```python
from Crypto.Cipher import AES
from pathlib import Path

key = b'\xb1\x88\xdf\xf7\xac\x59\x24\x97\xcd\xe2\x18\x9e\xd4\x53\x92\xe6'
cipher = AES.new(key, AES.MODE_ECB)
enc_img = Path("flag.png").read_bytes()
dec_img = bytearray()
for i in range(0, len(enc_img), 16):
    dec_img += cipher.decrypt(enc_img[i:i + 16])
Path("actual_flag.png").write_bytes(dec_img)
```

Viewing the decrypted image yields the flag!

Flag: `gigem{its_encryption_all_the_way_down}`
