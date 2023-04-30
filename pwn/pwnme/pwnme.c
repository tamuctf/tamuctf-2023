#include "foo.h"

asm( 
    "mov rax, qword ptr [rdi]\n\t"
    "ret\n\t"
    );

int main() {
    asm("sub rsp, 0x18\n\t");
    pwnme();
    asm("add rsp, 0x18\n\t");
}

asm(
    "sub rax, rsi\n\t"
    "ret\n\t"
    );
