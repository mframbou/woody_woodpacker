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

void print_error(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
}

int is_elf_file(unsigned char *file_content, size_t file_size)
{
    if (file_size < 4)
        return 0;
    // https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    // 0x00	4	e_ident[EI_MAG0] through e_ident[EI_MAG3]	0x7F followed by ELF(45 4c 46) in ASCII; these four bytes constitute the magic number.
    if (file_content[0] == 0x7f && file_content[1] == 'E' && file_content[2] == 'L' && file_content[3] == 'F')
        return 1;
    return 0;
}

int is_64bit_elf(unsigned char *file_content, size_t file_size)
{
    // 0x04	1	e_ident[EI_CLASS]	This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively.
    if (file_size < 5)
        return 0;
    if (file_content[4] == 2)
        return 1;
    return 0;
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

	size_t file_size = lseek(fd, 0, SEEK_END);
	if (file_size == -1)
	{
		perror("lseek");
		return EXIT_FAILURE;
	}

	void *file_content = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (file_content == MAP_FAILED)
	{
		perror("mmap");
		return EXIT_FAILURE;
	}

	if (close(fd) == -1)
	{
		perror("close");
		return EXIT_FAILURE;
	}

    if (!is_elf_file(file_content, file_size))
    {
        print_error("Not an ELF file");
        return EXIT_FAILURE;
    }

    if (!is_64bit_elf(file_content, file_size))
    {
        print_error("Not a 64-bit ELF file");
        return EXIT_FAILURE;
    }


	// printf("Original file:\n");
	// for (size_t i = 0; i < file_size; i++)
	// {
	// 	printf("%02x", ((unsigned char *)file_content)[i]);
	// 	if (i % 16 == 15)
	// 		printf("\n");
	// }
	// printf("\n");

	// // encrypt the file
	// unsigned char key = 0x42;

	// for (size_t i = 0; i < file_size; i++)
	// 	((unsigned char *)file_content)[i] += key;

	// for (size_t i = 0; i < file_size; i++)
	// 	((unsigned char *)file_content)[i] ^= key;

	// for (size_t i = 0; i < file_size; i++)
	// 	((unsigned char *)file_content)[i] -= key;

	// // print the file in hex
	// printf("Encrypted:\n");
	// for (size_t i = 0; i < file_size; i++)
	// {
	// 	printf("%02x", ((unsigned char *)file_content)[i]);
	// 	if (i % 16 == 15)
	// 		printf("\n");
	// }
	// printf("\n");

	// // decrypt the file
	// for (size_t i = 0; i < file_size; i++)
	// 	((unsigned char *)file_content)[i] += key;

	// for (size_t i = 0; i < file_size; i++)
	// 	((unsigned char *)file_content)[i] ^= key;

	// for (size_t i = 0; i < file_size; i++)
	// 	((unsigned char *)file_content)[i] -= key;

	// // print the file in hex
	// printf("Decrypted:\n");
	// for (size_t i = 0; i < file_size; i++)
	// {
	// 	printf("%02x", ((unsigned char *)file_content)[i]);
	// 	if (i % 16 == 15)
	// 		printf("\n");
	// }
	// printf("\n");



	if (munmap(file_content, file_size) == -1)
	{
		perror("munmap");
		return EXIT_FAILURE;
	}
}