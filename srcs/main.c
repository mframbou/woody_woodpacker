#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <sys/stat.h>

unsigned int payload_size = 200;


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

	unsigned char *file_content = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
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
	// Elf64_Shdr *section_header_table = (Elf64_Shdr *)(file_content + header.e_shoff);
	// We find an executable segment, find the last section in this segment, then try to expand it using the free padding space, try this for every executable segment
	for (unsigned int i = 0; i < header.e_phnum; i++)
	{
		if (program_header_table[i].p_type == PT_LOAD && program_header_table[i].p_flags & PF_X)
		{
			printf("Exec segment from 0x%08lx to 0x%08lx (size: %ld bytes)\n", program_header_table[i].p_offset, program_header_table[i].p_offset + program_header_table[i].p_memsz, program_header_table[i].p_memsz);

			// list all sections in the segment
			uint64_t segment_start = program_header_table[i].p_offset;
			uint64_t segment_end = program_header_table[i].p_offset + program_header_table[i].p_memsz;

			for (unsigned int j = 0; j < header.e_shnum; j++)
			{
				uint64_t section_start = section_header_table[j].sh_offset;
				uint64_t section_end = section_header_table[j].sh_offset + section_header_table[j].sh_size;
				if (section_end == segment_end) {
					printf("Section %s at 0x%08lx (size: %ld bytes)\n", (char *)(file_content + shstrtab_section_header->sh_offset + section_header_table[j].sh_name), section_start, section_header_table[j].sh_size);
					
					// find next section start
					// TODO check if its last section of the file
					uint64_t next_section_start = section_header_table[j + 1].sh_offset;

					uint64_t available_space = next_section_start - section_end;
					if (available_space < payload_size)
					{
						printf("Not enough space for the payload\n");
						continue;
					}

					printf("Found %ld bytes of free space in the segment\n", available_space);

					// now we expand the section and segment to fit the payload
					Elf64_Phdr *segment = &(program_header_table[i]);
					segment->p_memsz += payload_size;
					segment->p_filesz += payload_size;

					Elf64_Shdr *section = &(section_header_table[j]);
					section->sh_size += payload_size;
				}

			}
		}
	}

	// write the result to a new file
	FILE *new_file = fopen("woody", "w");
	if (new_file == NULL)
	{
		perror("fopen");
		munmap(file_content, file_size);
		return EXIT_FAILURE;
	}

	chmod("woody", 0777);

	if (fwrite(file_content, 1, file_size, new_file) != file_size)
	{
		perror("fwrite");
		fclose(new_file);
		munmap(file_content, file_size);
		return EXIT_FAILURE;
	}


	
	

	if (munmap(file_content, file_size) == -1)
	{
		perror("munmap");
		return EXIT_FAILURE;
	}
}