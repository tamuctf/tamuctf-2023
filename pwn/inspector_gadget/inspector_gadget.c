#include <stdio.h>
#include <unistd.h>

void setup() {
        // Ignore, stuff to set up server I/O correctly
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
}

void pwnme() {
        char buf[0x10];

        puts("pwn me");
        read(0, buf, 0x60);

        return;
}

int main(int argc, char* argv[]) {
        setup();

        puts("i've got 2 words for ya");
        pwnme();

        puts("cool.");
}

