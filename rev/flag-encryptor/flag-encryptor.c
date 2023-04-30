#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "tiny-AES-c/aes.h"

unsigned long foo_size = 0x1122334455667788;
unsigned long mprot_size = 0x1122334455667788;
unsigned char enc_key[16] = "AAAABBBBCCCCDDDD";

void __attribute__((section(".foo"))) foo() {
    FILE *f = fopen("flag.png", "rb+");
    if (f == NULL) {
        puts("No flag.png to encrypt :(");
        return;
    }

    if (fseek(f, 0, SEEK_END) == -1) {
        perror("first fseek");
        return;
    }
    long f_size = ftell(f);
    if (f_size == -1) {
        perror("ftell");
        return;
    }
    f_size += (16 - (f_size%16));

    unsigned char* buf = calloc(1, f_size);
    if (buf == NULL) {
        puts("calloc failed");
        return;
    }
    
    if (fseek(f, 0, SEEK_SET) == -1) {
        perror("second fseek");
        return;
    }
    fread(buf, f_size, 1, f);
    
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, enc_key);
    for (long i = 0; i < f_size; i += 16) {
        AES_ECB_encrypt(&ctx, buf+i);
    }

    if (fseek(f, 0, SEEK_SET) == -1) {
        perror("third fseek");
        return;
    }
    fwrite(buf, f_size, 1, f);

    exit(0);
}

void decrypt(unsigned char* bytes) {
    for (unsigned long i = 0; i < foo_size; i++) {
        bytes[i] ^= enc_key[i % 16];
    }
}

void main () {
    mprotect( (unsigned long)foo & 0xfffffffffffff000, mprot_size, PROT_READ|PROT_WRITE|PROT_EXEC); // Needs to be page aligned
    decrypt((unsigned char*)foo);
    foo();
    return 0;
}
