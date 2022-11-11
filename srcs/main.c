#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

void usage()
{
	fprintf(stderr, "Usage: woody_woodpacker [options]\n");
}

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		usage();
		return EXIT_FAILURE;
	}

	// open the file
	int fd = open(argv[1], O_RDONLY);
	if (fd == -1)
	{
		perror("open");
		return EXIT_FAILURE;
	}

	size_t size = lseek(fd, 0, SEEK_END);
	if (size == -1)
	{
		perror("lseek");
		return EXIT_FAILURE;
	}

	void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (ptr == MAP_FAILED)
	{
		perror("mmap");
		return EXIT_FAILURE;
	}

	if (close(fd) == -1)
	{
		perror("close");
		return EXIT_FAILURE;
	}

	printf("Original file:\n");
	for (size_t i = 0; i < size; i++)
	{
		printf("%02x", ((unsigned char *)ptr)[i]);
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");

	// encrypt the file
	unsigned char key = 0x42;

	for (size_t i = 0; i < size; i++)
		((unsigned char *)ptr)[i] += key;

	for (size_t i = 0; i < size; i++)
		((unsigned char *)ptr)[i] ^= key;

	for (size_t i = 0; i < size; i++)
		((unsigned char *)ptr)[i] -= key;

	// print the file in hex
	printf("Encrypted:\n");
	for (size_t i = 0; i < size; i++)
	{
		printf("%02x", ((unsigned char *)ptr)[i]);
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");

	// decrypt the file
	for (size_t i = 0; i < size; i++)
		((unsigned char *)ptr)[i] += key;

	for (size_t i = 0; i < size; i++)
		((unsigned char *)ptr)[i] ^= key;

	for (size_t i = 0; i < size; i++)
		((unsigned char *)ptr)[i] -= key;

	// print the file in hex
	printf("Decrypted:\n");
	for (size_t i = 0; i < size; i++)
	{
		printf("%02x", ((unsigned char *)ptr)[i]);
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");



	if (munmap(ptr, size) == -1)
	{
		perror("munmap");
		return EXIT_FAILURE;
	}
}