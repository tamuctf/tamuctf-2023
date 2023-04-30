#include <stdio.h>
#include <stdlib.h>

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    unsigned int x;
    int offset;

    printf("Please enter &main: ");
    scanf("%x", &x);

    // find the offset for &seed
    offset = 11971;
    x = x + offset;

    srand(x);
    for(int i=1; i<=7; i++) {
        printf("Randon number: %d\n", rand());
    }
}
