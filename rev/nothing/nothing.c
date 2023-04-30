#include <stdio.h>
#include <string.h>

char* fun(char* p_addr) {
    puts("also not here");
    return p_addr + 0x400000;
}

int main(int argc, char* argv[]) {
    puts("not here");

    char* addr = fun(((char*)&&rethere) - 0x400000);
    asm volatile(
        "push %0\n"
        "ret"
    :
    : "g"(addr)
    );

    rethere:
    if (argc != 2) {
        return -1;
    }

    char check[] = "ghefi~nbqVsdyRh`e\x7fvL`}sHhku|n|sb";
    char message[] = {'g', 'o', 'o', 'd', '\x00'};
    for (size_t i = 0; i < strlen(argv[1]); i++) {
        argv[1][i] ^= i;
    }

    if (strcmp(argv[1], check) == 0) {
        puts(message);
    }

    return 0;

}
