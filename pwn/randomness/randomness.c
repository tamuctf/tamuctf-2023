#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    char* argv[] = {"/bin/cat", "flag.txt", NULL};
    execve(argv[0], argv, NULL);
}

void foo() {
    unsigned long seed;
    puts("Enter a seed:");
    scanf("%lu", &seed);
    srand(seed);
}

void bar() {
    unsigned long a;

    puts("Enter your guess:");
    scanf("%lu", a);

    if (rand() == a) {
        puts("correct!");
    } else {
        puts("incorrect!");
    }
}


int main() {
    puts("hello!");
    foo();
    bar();
    puts("goodbye!");
}
