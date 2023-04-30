# nothing

Author: `anomie`

This program seems to be taunting me, I'm sure there's something here...

## Dev notes
Only given file is the binary `nothing`.

## Solution
Opening the binary in Ghidra initially reveals nothing about the flag-checking logic. However, upon closer inspection, there is a sneaky `push` before a `ret` that prevents Ghidra from disassembling a certain section of code. Here's what it looks like:
```c
undefined8 UndefinedFunction_001011ab(void)

{
  int iVar1;
  undefined8 uVar2;
  size_t sVar3;
  long unaff_RBP;
  
  if (*(int *)(unaff_RBP + -0x54) == 2) {
    *(undefined8 *)(unaff_RBP + -0x40) = 0x626e7e6966656867;
    *(undefined8 *)(unaff_RBP + -0x38) = 0x6068527964735671;
    *(undefined8 *)(unaff_RBP + -0x30) = 0x48737d604c767f65;
    *(undefined8 *)(unaff_RBP + -0x28) = 0x62737c6e7c756b68;
    *(undefined *)(unaff_RBP + -0x20) = 0;
    *(undefined *)(unaff_RBP + -0x45) = 0x67;
    *(undefined *)(unaff_RBP + -0x44) = 0x6f;
    *(undefined *)(unaff_RBP + -0x43) = 0x6f;
    *(undefined *)(unaff_RBP + -0x42) = 100;
    *(undefined *)(unaff_RBP + -0x41) = 0;
    *(undefined8 *)(unaff_RBP + -8) = 0;
    while( true ) {
      sVar3 = strlen(*(char **)(*(long *)(unaff_RBP + -0x60) + 8));
      if (sVar3 <= *(ulong *)(unaff_RBP + -8)) break;
      *(byte *)(*(long *)(unaff_RBP + -8) + *(long *)(*(long *)(unaff_RBP + -0x60) + 8)) =
           *(byte *)(*(long *)(unaff_RBP + -8) + *(long *)(*(long *)(unaff_RBP + -0x60) + 8)) ^
           (byte)*(undefined8 *)(unaff_RBP + -8);
      *(long *)(unaff_RBP + -8) = *(long *)(unaff_RBP + -8) + 1;
    }
    iVar1 = strcmp(*(char **)(*(long *)(unaff_RBP + -0x60) + 8),(char *)(unaff_RBP + -0x40));
    if (iVar1 == 0) {
      puts((char *)(unaff_RBP + -0x45));
    }
    uVar2 = 0;
  }
  else {
    uVar2 = 0xffffffff;
  }
  return uVar2;
}
```
If we squint hard enough and look past the crazy type-casting, we can see that a 32-byte key is loaded on the stack in 4 immediates. The user input is read from `argv[1]` and xor'd with a loop index. If the xor'd input matches the key (i.e. `strcmp` determines the inputs are equal), then we know we have the flag. I extracted the key and xor'd it with a counter in Python to get the flag:

```python
key = b"\x67\x68\x65\x66\x69\x7e\x6e\x62\x71\x56\x73\x64\x79\x52\x68\x60\x65\x7f\x76\x4c\x60\x7d\x73\x48\x68\x6b\x75\x7c\x6e\x7c\x73\x62"
print("".join(chr(i ^ b) for i, b in enumerate(key)))
```

Flag: `gigem{hey_you_found_the_program}`
