#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <sys/stat.h>

unsigned int payload_size = 4096;


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
	if (file_content[EI_MAG0] == ELFMAG0 && file_content[EI_MAG1] == ELFMAG1 && file_content[EI_MAG2] == ELFMAG2 && file_content[EI_MAG3] == ELFMAG3)
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

	if (file_size < EI_NIDENT) // If we cannot get identification infos (magic number, architecture etc.)
	{
		fprintf(stderr, "File is too small to be an ELF file\n");
		close(fd);
		return 1;
	}

	unsigned char *file_content = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file_content == MAP_FAILED)
	{
		perror("mmap");
		return EXIT_FAILURE;
	}

	// from the man, we can close the fd without invalidating the mapping, so close is as soon as possible
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

	if (file_content[EI_VERSION] != EV_CURRENT)
	{
		fprintf(stderr, "Invalid ELF version\n");
		munmap(file_content, file_size);
		return EXIT_FAILURE;
	}

	if (file_content[EI_CLASS] != ELFCLASS64)
	{
		fprintf(stderr, "Only 64-bit ELF files are supported\n");
		munmap(file_content, file_size);
		return EXIT_FAILURE;
	}

	if (file_size < sizeof(Elf64_Ehdr))
	{
		fprintf(stderr, "File is too small to contain an ELF header\n");
		munmap(file_content, file_size);
		return EXIT_FAILURE;
	}

	Elf64_Ehdr header = *(Elf64_Ehdr *)file_content;
	void *header_section_start = file_content + header.e_shoff;
	size_t header_section_size = header.e_shentsize;
	size_t header_section_entries_count = header.e_shnum;
	size_t shstrtab_section_index = header.e_shstrndx;


	if ((unsigned char *)header_section_start + header_section_size * header_section_entries_count > file_content + file_size)
	{
		fprintf(stderr, "Invalid section header table\n");
		munmap(file_content, file_size);
		return EXIT_FAILURE;
	}

	if (shstrtab_section_index >= header_section_entries_count)
	{
		fprintf(stderr, "Invalid shstrtab section index\n");
		munmap(file_content, file_size);
		return EXIT_FAILURE;
	}

	Elf64_Shdr *section_header_table = (Elf64_Shdr *)header_section_start;
	Elf64_Shdr *shstrtab_section_header = section_header_table + shstrtab_section_index;

	if (shstrtab_section_header->sh_type != SHT_STRTAB)
	{
		fprintf(stderr, "Invalid shstrtab section type\n");
		munmap(file_content, file_size);
		return EXIT_FAILURE;
	}

	if (shstrtab_section_header->sh_offset + shstrtab_section_header->sh_size > file_size)
	{
		fprintf(stderr, "Invalid shstrtab section size\n");
		munmap(file_content, file_size);
		return EXIT_FAILURE;
	}

	Elf64_Phdr *program_header_table = (Elf64_Phdr *)(file_content + header.e_phoff);
	size_t program_header_entries_count = header.e_phnum;
	Elf64_Phdr *last_loaded_segment = NULL; // we need to find the last loaded segment and expand it
	// we cannot simply add another program header, since it will move all offsets in the file breaking everything.
	unsigned int highest_address = 0;

	if ((unsigned char *)program_header_table + sizeof(Elf64_Phdr) * program_header_entries_count > file_content + file_size)
	{
		fprintf(stderr, "Invalid program header table\n");
		munmap(file_content, file_size);
		return EXIT_FAILURE;
	}


	for (size_t i = 0; i < program_header_entries_count; i++)
	{
		if (program_header_table[i].p_type == PT_LOAD)
		{
			if (last_loaded_segment == NULL || program_header_table[i].p_vaddr > highest_address)
			{
				last_loaded_segment = program_header_table + i;
				highest_address = program_header_table[i].p_vaddr;
			}
		}
	}

	if (last_loaded_segment == NULL)
	{
		fprintf(stderr, "No loadable segment found\n");
		munmap(file_content, file_size);
		return EXIT_FAILURE;
	}

	printf("Last loaded segment: \n");
	printf("p_type: %d\n", last_loaded_segment->p_type);
	printf("p_flags: %d\n", last_loaded_segment->p_flags);
	printf("p_offset: %lu\n", last_loaded_segment->p_offset);
	printf("p_vaddr: %lu\n", last_loaded_segment->p_vaddr);
	printf("p_paddr: %lu\n", last_loaded_segment->p_paddr);
	printf("p_filesz: %lu\n", last_loaded_segment->p_filesz);
	printf("p_memsz: %lu\n", last_loaded_segment->p_memsz);
	printf("p_align: %lu\n", last_loaded_segment->p_align);

	// now we expand the last segment
	


	// printf("File size: %zu\n", file_size);


	if (munmap(file_content, file_size) == -1)
	{
		perror("munmap");
		return EXIT_FAILURE;
	}
}