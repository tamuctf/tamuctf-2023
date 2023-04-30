#include "foo.h"

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
    system("/bin/bash");
}

void pwnme() {
    char buf[0x10];

    setup();
    puts("pwn me");
    read(0, buf, 0x48);

    return;
}
