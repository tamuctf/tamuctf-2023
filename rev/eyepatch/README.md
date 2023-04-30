# EyePatch

Author: `RogueGuardian`

Corporate said we were behind schedule, so we pushed our untested code to production. Unfortunately, we realized that we had some unintended bugs in our code. We need you to fix the binary before corporate gets word of this.

We narrowed down what you need to fix to 3 issues:
1. A numerical mistype 
2. A flipped comparison 
3. A wrong math operation between two numbers

Each issue is a single byte that needs to be changed. Note that `main()` is written as intended, just change what is in the function bodies to correct the code. Once you think you have the correct binary, uphold the file to our server, and we'll verify if it's correct.

## Solution
Use Ghidra to binpatch. Just right-click on the problematic disassembly, select "Patch Instruction", then make the necessary changes.

Issue #1 is in `fib()`:
```c
int fib(int param_1)

{
  int iVar1;
  int iVar2;
  
  if (param_1 == 0) {
    iVar2 = 0;
  }
  else if (param_1 == 1) {
    // NOTE: change this to 1
    iVar2 = 2;
  }
  else {
    iVar1 = fib(param_1 + -1);
    iVar2 = fib(param_1 + -2);
    iVar2 = iVar2 + iVar1;
  }
  return iVar2;
}
```
Change the immediate from 2 to 1.

Issue #2 is in `int_relu()`:
```c
int int_relu(int param_1) {
  // NOTE: change this to param_1 < 0
  if (-1 < param_1) {
    param_1 = 0;
  }
  return param_1;
}
```
Change the conditional jump instruction to `JS` (or equivalent).

Issue #3 is in `det()`.
```c
float det(float *param_1) {
  // NOTE: change + to -
  return param_1[3] * *param_1 + param_1[1] * param_1[2];
}
```
Change `ADDSS` to `SUBSS`.

Flag: `gigem{i_hope_you_didnt_pwn_our_infra}`
