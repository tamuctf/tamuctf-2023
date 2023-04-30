#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char charset[] = "abcdefghijklmnopqrstuvwxyz1234567890{}_";
const char sbox[] = "4piq9zovafg8{1hkcm7std03xle}ry6w_ujn52b";
const size_t charset_len = strlen(charset);

void* foo (void* addr) {
    return addr + 0x400000;
}

void __attribute__((constructor)) before_main (int argc, char* argv[]) {
    void* addr = foo(((void*)&&rethere) - 0x400000);
    asm volatile(
        "push %0\n"
        "ret\n"
    :
    : "g"(addr)
    );
rethere:

    if (argc != 2)
        return;

    char check[] = {'o', 'a', 'o', '9', '{', '5', 'i', 'n', '1', '7', 's', 'm', 't', 'i', 's', 'n', 'm', '6', 'b', 'm', 't', '1', 'b', 'p', 'r', 'z', 'n', 'm', 'r', 'b', '{', 'y', 'e', '1', '2'};
    size_t check_len = strlen(check);
    size_t inp_len = strlen(argv[1]);

    if (check_len != inp_len)
        return;

    for (size_t i = 0; i < inp_len; i++) {
        size_t index = (size_t)(strchr(charset, argv[1][i]) - charset);
        if (index >= charset_len)
            return;

        if (sbox[index] != check[i])
            return;
    }

    char win_message[] = {'c', 'o', 'r', 'r', 'e', 'c', 't', ' ', 'f', 'l', 'a', 'g', '!', '\0'};
    puts(win_message);
}

void main () {
    puts("this is main");
}
