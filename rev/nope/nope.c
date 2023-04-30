#include <stdio.h>
#include <stdlib.h>

// gcc nope.c -masm=intel -o nope -w

const char pad[] = "\xbd\xbc\xb9\xfe\xd4\xbd\xee\xfe\xba\xfa\xab\xde\xad\xe8\xf5\xc2\xbc\xac\xee\xea\xe9\xf9\xea";

/*
 * r9 = address of pad[i]
 * r10 = value at pad[i]
 * r11 = address of argv[i]
 */


int strcmp(char *p1, char *p2) {
    unsigned char *s1 = (unsigned char *) p1;
    unsigned char *s2 = (unsigned char *) p2;
    unsigned char c1, c2;
    do {
        c1 = (unsigned char) *s1++;
        c2 = (unsigned char) *s2++;
        if (c1 == '\0')
            return c1 - c2;
    } while (c1 == c2);
    return c1 - c2;
}

int strlen(unsigned char* str) {
	unsigned char *s;

	for (s = str; *s; ++s);

	return(s - str);
}


char fun2(char a, char b) {
        asm volatile(
                "mov r10b, byte ptr [r11 + 0x1]\n\t"
                );
        b = a ^ b;
        asm volatile(
                "neg r10\n\t"
                "xor r10b, byte ptr [r9]\n\t"
                "add r11, 1\n\t"
            );
        return b;
}

void fun1(char* str, int len) {
    for (int i=0; i<=len; i++) {
        asm volatile(
                "mov r10, 0\n\t"
            );
        str[i] = fun2(str[i], i);
        asm volatile(
                "mov byte ptr [r11], r10b\n\t"
                "dec r9\n\t"
                );
    }
}

    
int main(int argc, char* argv[]) {
        char check[] = "\x73\x6e\x70\x71\x7d\x29\x26\x69\x67\x7d\x2a\x7f\x64\x68\x2e\x69\x7c\x70\x75\x32\x34\x2f\x3e";

        asm volatile(
                "lea r9, [rip+0xceb]\n\t"
            );

        if (argc < 2) {
                goto bye;
        }
        
        int i_len = strlen(argv[1]);
        
        asm volatile(
                "mov r11, rdi\n\t"
            );
        
        int check_len = strlen(check);

        asm volatile(
                "sub r11, 1\n\t"
            );

        
        if (check_len != i_len) {
            goto bye;
        }

        
        asm volatile(
                "add r9, 0x27\n\t"
            );

        fun1(argv[1], check_len);

        if (strcmp(argv[1], check)) {
               goto bye;
        }
        
        printf("Congrats, you found the flag!\n");
        return 0;

bye:
        printf("nope.\n");
        exit(1);
}

