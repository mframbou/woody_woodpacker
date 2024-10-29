#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <sys/stat.h>

unsigned int payload_size = 4096;

unsigned int		align(unsigned int value, int base)
{
	return (value + (base - 1)) & -base;
}

void usage()
{
	fprintf(stderr, "Usage: woody_woodpacker [options]\n");
}

void print_error(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
}

Elf64_Shdr		*add_new_section_header64(void *map, Elf64_Shdr *shdr, \
						uint64_t shnum, size_t filesize)
{
	unsigned int 	index;
	int		added;
	uint64_t	prev_comment_offset;
	Elf64_Shdr	*prev_shdr;
	Elf64_Shdr	*new_shdr;
	uint64_t	data_addr;
	uint64_t 	data_offset;

	index = 0;
	added = 0;
	prev_comment_offset = 0;
	while (index < shnum + 1)
	{
		/* if the section is added then we need to shift the sh_offset of other consecutive section after our section */
		if (added)
		{
	    	if (shdr->sh_type == SHT_NOTE)
	    	{
	    	    prev_comment_offset = shdr->sh_offset;
				shdr->sh_offset = prev_shdr->sh_offset + prev_shdr->sh_size;
	    	}
	    	else if (prev_comment_offset != 0 && prev_shdr->sh_type == SHT_NOTE)
	    	{
				shdr->sh_offset = prev_shdr->sh_offset + (shdr->sh_offset - prev_comment_offset);
				prev_comment_offset = 0;
	    	}
			/* Handle comment section alignement */
			else if (shdr->sh_type == SHT_PROGBITS && shdr->sh_flags == SHF_STRINGS + SHF_MERGE)
			{
				prev_comment_offset = shdr->sh_offset;
				shdr->sh_offset = prev_shdr->sh_offset + prev_shdr->sh_size;
			}
			//else if (prev_comment_offset != 0 && !(shdr->sh_type == SHT_PROGBITS && shdr->sh_flags == SHF_STRINGS + SHF_MERGE))
			else if (prev_comment_offset != 0 && prev_shdr->sh_flags == SHF_STRINGS + SHF_MERGE)
			{
				shdr->sh_offset = prev_shdr->sh_offset + (shdr->sh_offset - prev_comment_offset);
				prev_comment_offset = 0;
			}
			else if (shdr->sh_type == SHT_PROGBITS && prev_shdr->sh_addralign != 1)
				shdr->sh_offset = prev_shdr->sh_offset + align(prev_shdr->sh_size, shdr->sh_addralign);
			else
				shdr->sh_offset = prev_shdr->sh_offset + prev_shdr->sh_size;
		}

		if (index != 0 && shdr->sh_addr == 0 && added == 0 && shdr->sh_name != 0)
		{
			/* shift the memory to create a new space for our section hedaer */
			memmove((void *)shdr + sizeof(Elf64_Shdr), (void *)shdr, filesize - ((size_t)shdr - (size_t)map));
			/* Initialize our section header */
			shdr->sh_name = 0x0;
			shdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
			if (prev_shdr->sh_type == SHT_NOBITS)
			{
				prev_shdr--;
				data_addr = prev_shdr->sh_addr;
				data_offset = prev_shdr->sh_offset;
				prev_shdr++;
				// bss offset = data offset + (bss_addr - data_addr)
				prev_shdr->sh_offset = data_offset + (prev_shdr->sh_addr - data_addr);
				shdr->sh_offset = prev_shdr->sh_offset + prev_shdr->sh_size;
				shdr->sh_addr = prev_shdr->sh_addr + prev_shdr->sh_size;
			}
			else
			{
				shdr->sh_offset = prev_shdr->sh_offset + align(prev_shdr->sh_size, prev_shdr->sh_addralign);
				shdr->sh_addr = prev_shdr->sh_addr + align(prev_shdr->sh_size, prev_shdr->sh_addralign);
			}
			shdr->sh_type = SHT_PROGBITS;
			shdr->sh_size = payload_size;
			shdr->sh_link = 0x0;
			shdr->sh_addralign = 0x1;
			shdr->sh_entsize = 0x0;
			added = 1;
			new_shdr = shdr;
		}
		prev_shdr = shdr;
		index++;
		shdr++;
	}
	return (new_shdr);
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

	Elf64_Shdr *new_shdr = add_new_section_header64(file_content, (Elf64_Shdr *)header_section_start, header.e_shnum, file_size);
	unsigned int new_file_size = file_size + payload_size + sizeof(Elf64_Shdr);

	// write the new file
	// FILE *new_file = fopen("woody", "w");
	// if (new_file == NULL)
	// {
	// 	perror("fopen");
	// 	return EXIT_FAILURE;
	// }

	// if (fwrite(file_content, 1, new_shdr->sh_offset, new_file) != new_shdr->sh_offset)
	// {
	// 	perror("fwrite");
	// 	return EXIT_FAILURE;
	// }

	
	

	if (munmap(file_content, file_size) == -1)
	{
		perror("munmap");
		return EXIT_FAILURE;
	}
}