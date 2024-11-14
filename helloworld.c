#include <unistd.h>
#include <stdlib.h>

int main() {
	write(1, "Hello world\n", 12);
	exit(0);
	write(1, "Ta gueule nono\n", 14);
}
