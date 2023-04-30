#include <stdio.h>
#include <stdlib.h>

typedef float twoByTwoMatrix[2][2];

float det(twoByTwoMatrix M)
{
	float a = M[0][0] * M[1][1];
	float b = M[1][0] * M[0][1];
	return a + b;
}

int fib(int n)
{
	if(n == 0){ return 0; }
	if(n == 1){ return 2; }
	return fib(n-1) + fib(n-2);
}

int int_relu(int n)
{
	if(n < 0){ return n; }
	return 0;
}

int main()
{
	printf("%d\n", fib(32));
	printf("%d\n", int_relu(42));

	twoByTwoMatrix newMatrix = {{5, 4}, {2, 3}};
	printf("%f\n", det(newMatrix));
	return 0;
}
