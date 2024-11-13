#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <sys/stat.h>

unsigned char payload_bin[] = {
	// 0xe9, 0xa5 => payload
	// 0xeb, 0x20 => decrypt
  0xe9, 0xa5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x48, 0x8b, 0x05, 0xe9, 0xff, 0xff, 0xff, 0x4c, 0x8b, 0x05, 0xea,
  0xff, 0xff, 0xff, 0x4c, 0x8d, 0x0d, 0xc6, 0xff, 0xff, 0xff, 0x4d, 0x01,
  0xc8, 0x4c, 0x89, 0xc3, 0x48, 0x8b, 0x0d, 0xc6, 0xff, 0xff, 0xff, 0x48,
  0xc7, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x49, 0x89, 0xc2, 0x48, 0xc7, 0xc0,
  0x0a, 0x00, 0x00, 0x00, 0x48, 0x89, 0xdf, 0x4c, 0x89, 0xd6, 0x48, 0xc7,
  0xc2, 0x07, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x39, 0xc2, 0x7d, 0x18,
  0x48, 0x89, 0xdf, 0x48, 0x01, 0xd7, 0x48, 0x0f, 0xb6, 0x37, 0x49, 0x89,
  0xc8, 0x4c, 0x31, 0xc6, 0x40, 0x88, 0x37, 0x48, 0xff, 0xc2, 0xeb, 0xe3,
  0x48, 0xc7, 0xc0, 0x0a, 0x00, 0x00, 0x00, 0x48, 0x89, 0xdf, 0x4c, 0x89,
  0xd6, 0x48, 0xc7, 0xc2, 0x05, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xeb, 0x0e,
  0x2e, 0x2e, 0x2e, 0x2e, 0x57, 0x4f, 0x4f, 0x44, 0x59, 0x2e, 0x2e, 0x2e,
  0x2e, 0x0a, 0x57, 0x56, 0x52, 0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
  0x48, 0x8d, 0x35, 0xe1, 0xff, 0xff, 0xff, 0x48, 0xc7, 0xc2, 0x0e, 0x00,
  0x00, 0x00, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48,
  0x8b, 0x05, 0x33, 0xff, 0xff, 0xff, 0x4c, 0x8d, 0x15, 0x27, 0xff, 0xff,
  0xff, 0x49, 0x29, 0xc2, 0x5a, 0x5e, 0x5f, 0x41, 0xff, 0xe2
};
uint64_t payload_size = 226;

unsigned char encryption_key = 0x42;

// https://tmpout.sh/1/2.html
// https://www.symbolcrash.com/2019/03/27/pt_note-to-pt_load-injection-in-elf/
// https://github.com/zznop/drow


void encrypt_section(Elf64_Shdr *section, unsigned char *file_content, unsigned char key)
{
	uint64_t section_start = section->sh_offset;
	uint64_t section_size = section->sh_size;
	void *section_content = file_content + section_start;

	// simple XOR encryption
	for (uint64_t i = 0; i < section_size; i++)
	{
		((unsigned char *)section_content)[i] ^= key;
	}
}


void usage()
{
	fprintf(stderr, "Usage: woody_woodpacker [source_exec]\n");
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

	// open the target ELF file
	int fd = open(argv[1], O_RDONLY);
	if (fd == -1)
	{
		perror("Cannot open file");
		return EXIT_FAILURE;
	}

	size_t file_size = lseek(fd, 0, SEEK_END);
	if (file_size == -1)
	{
		perror("Cannot lseek file");
		return EXIT_FAILURE;
	}


	unsigned char *file_content = malloc(file_size);
	if (file_content == NULL)
	{
		perror("Malloc failed");
		return EXIT_FAILURE;
	}

	if (lseek(fd, 0, SEEK_SET) == -1)
	{
		perror("Cannot lseek file");
		return EXIT_FAILURE;
	}

	if (read(fd, file_content, file_size) == -1)
	{
		perror("Cannot read file");
		return EXIT_FAILURE;
	}

	if (close(fd) == -1)
	{
		perror("Cannot close file");
		return EXIT_FAILURE;
	}

	if (file_size < EI_NIDENT) // If we cannot get identification infos (magic number, architecture etc.)
	{
		fprintf(stderr, "File is too small to be an ELF file\n");
		free(file_content);
		return 1;
	}

    if (!is_elf_file(file_content, file_size))
    {
		fprintf(stderr, "File is not an ELF file\n");
		free(file_content);
        return EXIT_FAILURE;
    }

	if (file_content[EI_VERSION] != EV_CURRENT)
	{
		fprintf(stderr, "File has invalid ELF version\n");
		free(file_content);
		return EXIT_FAILURE;
	}

	if (file_content[EI_CLASS] != ELFCLASS64)
	{
		fprintf(stderr, "Only 64-bit ELF files are supported\n");
		free(file_content);
		return EXIT_FAILURE;
	}

	if (file_size < sizeof(Elf64_Ehdr))
	{
		fprintf(stderr, "File is too small to contain an ELF header\n");
		free(file_content);
		return EXIT_FAILURE;
	}

	Elf64_Ehdr *header = (Elf64_Ehdr *)file_content;

	void *header_section_start = file_content + header->e_shoff;
	size_t header_section_size = header->e_shentsize;
	size_t header_section_entries_count = header->e_shnum;
	size_t shstrtab_section_index = header->e_shstrndx;

	if ((unsigned char *)header_section_start + header_section_size * header_section_entries_count > file_content + file_size)
	{
		fprintf(stderr, "Invalid section header table\n");
		free(file_content);
		return EXIT_FAILURE;
	}

	if (shstrtab_section_index >= header_section_entries_count)
	{
		fprintf(stderr, "Invalid shstrtab section index\n");
		free(file_content);
		return EXIT_FAILURE;
	}

	Elf64_Shdr *section_header_table = (Elf64_Shdr *)header_section_start;
	Elf64_Shdr *shstrtab_section_header = section_header_table + shstrtab_section_index;

	if (shstrtab_section_header->sh_type != SHT_STRTAB)
	{
		fprintf(stderr, "Invalid shstrtab section type\n");
		free(file_content);
		return EXIT_FAILURE;
	}

	if (shstrtab_section_header->sh_offset + shstrtab_section_header->sh_size > file_size)
	{
		fprintf(stderr, "Invalid shstrtab section size\n");
		free(file_content);
		return EXIT_FAILURE;
	}


	void *payload_content = malloc(payload_size);
	if (payload_content == NULL)
	{
		perror("malloc");
		free(file_content);
		return EXIT_FAILURE;
	}

	memcpy(payload_content, payload_bin, payload_size);

	Elf64_Phdr *program_header_table = (Elf64_Phdr *)(file_content + header->e_phoff);


		// encrypt the payload
	
	// find .text section
	Elf64_Shdr *text_section = NULL;
	for (unsigned int i = 0; i < header->e_shnum; i++)
	{
		if (strcmp((char *)(file_content + shstrtab_section_header->sh_offset + section_header_table[i].sh_name), ".text") == 0)
		{
			printf("Found section %s\n", (char *)(file_content + shstrtab_section_header->sh_offset + section_header_table[i].sh_name));
			text_section = &(section_header_table[i]);
			break;
		}
	}

	if (text_section == NULL)
	{
		fprintf(stderr, "Could not find .text section\n");
		free(file_content);
		return EXIT_FAILURE;
	}
	
	// encrypt_section(text_section, file_content, encryption_key);

	// inject decryption values into the payload
	*(uint64_t *)(payload_content + 2+8) = (uint64_t)encryption_key;
	*(uint64_t *)(payload_content + 2+8+8) = text_section->sh_size;

	// find segment where .text section is located
	Elf64_Phdr *text_segment = NULL;
	for (unsigned int i = 0; i < header->e_phnum; i++)
	{
		if (program_header_table[i].p_offset <= text_section->sh_offset && program_header_table[i].p_offset + program_header_table[i].p_filesz >= text_section->sh_offset + text_section->sh_size)
		{
			text_segment = &(program_header_table[i]);
			break;
		}
	}
	
	if (text_segment == NULL)
	{
		fprintf(stderr, "Could not find segment for .text section\n");
		free(file_content);
		return EXIT_FAILURE;
	}

	// printf("Encrypted .text section\n");
	
	int found_cave = 0;
	// Elf64_Shdr *section_header_table = (Elf64_Shdr *)(file_content + header->e_shoff);
	// We find an executable segment, find the last section in this segment, then try to expand it using the free padding space, try this for every executable segment
	for (unsigned int i = 0; i < header->e_phnum; i++)
	{
		if (found_cave)
			break;

		if (program_header_table[i].p_type == PT_LOAD && program_header_table[i].p_flags & PF_X)
		{
			printf("Exec segment from 0x%08lx to 0x%08lx (size: %ld bytes)\n", program_header_table[i].p_offset, program_header_table[i].p_offset + program_header_table[i].p_memsz, program_header_table[i].p_memsz);

			// list all sections in the segment
			uint64_t segment_start = program_header_table[i].p_offset;
			uint64_t segment_end = program_header_table[i].p_offset + program_header_table[i].p_memsz;


			for (unsigned int j = 0; j < header->e_shnum; j++)
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

					printf("Found %ld bytes of free space in the segment (payload size: %ld)\n", available_space, payload_size);
					if (payload_size > available_space)
					{
						printf("Payload is too big\n");
						continue;
					}

					void *payload_start = file_content + section_start + section_header_table[j].sh_size;
					uint64_t new_entry_point = section_start + section_header_table[j].sh_size;

					// now we expand the section and segment to fit the payload
					Elf64_Phdr *segment = &(program_header_table[i]);
					segment->p_memsz += payload_size;
					segment->p_filesz += payload_size;

					Elf64_Shdr *section = &(section_header_table[j]);
					section->sh_size += payload_size;

					// now modify entry point to point to the payload
					printf("Current entry point: 0x%08lx\n", header->e_entry);
					uint64_t old_entry_point = header->e_entry;
					header->e_entry = new_entry_point;
					printf("New entry point: 0x%08lx\n", new_entry_point);

					uint64_t entry_delta = new_entry_point - old_entry_point;
					printf("Entry point delta: 0x%lx\n", entry_delta);

					// inject the delta into the payload starting at the 3rd byte
					*(uint64_t *)(payload_content + 2) = entry_delta;


					// TODO TEMP set flags to RWX for testing (otherwise segfault on write decryption)
					segment->p_flags = PF_R | PF_W | PF_X;


					// find the vaddr where the payload will be loaded
					uint64_t payload_vaddr = segment->p_vaddr + segment->p_memsz - payload_size; // vaddr where the payload will be loaded
					printf("Payload will be loaded at 0x%08lx\n", payload_vaddr);
					uint64_t text_section_vaddr = text_segment->p_vaddr + (text_section->sh_offset - text_segment->p_offset);
					printf("Text section is loaded at 0x%08lx\n", text_section_vaddr);
					printf("Delta: %lld\n", (long long)text_section_vaddr - (long long)payload_vaddr);

					*(uint64_t *)(payload_content + 2+8+8+8) = text_section_vaddr - payload_vaddr;

					// add a jump to the original entry point
					// E9 xx xx xx xx
					// *(uint8_t *)(payload_content + payload_size - 9) = 0xE9;
					// *(uint64_t *)(payload_content + payload_size - 8) = new_entry_point;
					
					// now insert the payload
					memcpy(payload_start, payload_content, payload_size);

					// TODO try to find a way to create codecave if there is no free space in the segment
					found_cave = 1;
				}
			}
			if (!found_cave)
			{
				printf("Segment did not fit in section or whatever\n");
				// possible due to PT_NOTE injection for instance, so now check if we can just expand the segment without expanding the section (eg if code is injected at the end of the file we should be able to expand the segment without expanding the section)

				// first check if its the highest virtual address PT_LOAD segment
				Elf64_Phdr *highest_vaddr_segment = NULL;
				for (unsigned int i = 0; i < header->e_phnum; i++)
				{
					if (program_header_table[i].p_type == PT_LOAD)
					{
						if (highest_vaddr_segment == NULL || program_header_table[i].p_vaddr > highest_vaddr_segment->p_vaddr)
							highest_vaddr_segment = &(program_header_table[i]);
					}
				}
				
				Elf64_Phdr *segment = &(program_header_table[i]);
				if (segment == highest_vaddr_segment)
				{
					printf("Segment is the highest virtual address PT_LOAD segment\n");
					// check if end of segment + payload_size overlaps other segment/section, if not we can expand

					uint64_t segment_end_offset = segment->p_offset + segment->p_memsz;
					uint64_t new_segment_end_offset = segment_end + payload_size;

					int overlaps = 0;
					// we use filesz and not memsz because we just want to see if we can expand in file. There might be overlap when loaded in memory but we don't care (since our code is executed first)
					// for instance with .bss section, which is probably loaded in same memory space as the segment but we don't care
					for (unsigned int j = 0; j < header->e_phnum; j++)
					{
						if (program_header_table[j].p_offset < new_segment_end_offset && program_header_table[j].p_offset + program_header_table[j].p_filesz > segment_end_offset)
						{
							Elf64_Phdr *overlapping_segment = &(program_header_table[j]);
							overlaps = 1;
							break;
						}
					}

					if (overlaps)
					{
						printf("Segment overlaps other segment, cannot expand\n");
						continue;
					}

					
					
					// simply expand the segment
					uint64_t old_entry_point = header->e_entry;
					uint64_t new_entry_point = segment->p_vaddr + segment->p_memsz;
					header->e_entry = new_entry_point;

					printf("Test: %08lx %08lx %08ld\n", old_entry_point, segment->p_vaddr, segment->p_memsz);

					uint64_t entry_delta = new_entry_point - old_entry_point;
					printf("NEW Entry point delta: 0x%lx\n", entry_delta);

					segment->p_memsz += payload_size;
					segment->p_filesz += payload_size;

					// inject the delta into the payload starting at the 3rd byte
					*(uint64_t *)(payload_content + 2) = entry_delta;

					file_content = realloc(file_content, file_size + payload_size); // expand the file to fit the payload
					memcpy(file_content + file_size, payload_content, payload_size);

					file_size += payload_size;
					printf("Successfully injected payload\n");
					printf("NEW New entry point: 0x%08lx\n", new_entry_point);
					found_cave = 1;
					break; // break cause header pointer is now invalid
				}
			}
		}
	}

	if (!found_cave)
	{
		// couldnt find already existing cave, so create one using PT_NOTE segment

		printf("didnt find a cave, try PT_NOTE inject\n");

		// find the highest virtual address in use
		uint64_t highest_vaddr = 0;
		for (unsigned int i = 0; i < header->e_phnum; i++)
		{
			if (program_header_table[i].p_vaddr + program_header_table[i].p_memsz > highest_vaddr)
			{
				highest_vaddr = program_header_table[i].p_vaddr + program_header_table[i].p_memsz;
			}
		}

		// now align it to page size
		uint64_t highest_vaddr_aligned = (highest_vaddr + 0xfff) & ~0xfff;
		printf("Highest virtual address: 0x%08lx\n", highest_vaddr_aligned);
	
		// find the PT_NOTE segment
		for (unsigned int i = 0; i < header->e_phnum; i++)
		{
			if (program_header_table[i].p_type == PT_NOTE)
			{
				printf("Found PT_NOTE segment\n");
				
				Elf64_Phdr *segment = &(program_header_table[i]);
				segment->p_type = PT_LOAD;
				segment->p_flags = PF_R | PF_X;
				// set high address to avoid collision
				segment->p_vaddr = highest_vaddr_aligned + file_size; // why is this + file_size mandatory ?? prob for alignment but why ?? (otherwise segfault)
				
				// remove all previous content (don't do += payload_size) otherwise if we later try to expand this segment it will segfault (why tho ?)
				segment->p_filesz = payload_size;
				segment->p_memsz = payload_size;

				segment->p_offset = file_size; // append the payload to the end of the file

				uint64_t old_entry_point = header->e_entry;
				uint64_t new_entry_point = segment->p_vaddr;
				header->e_entry = new_entry_point;

				uint64_t entry_delta = new_entry_point - old_entry_point;
				printf("Entry point delta: 0x%lx\n", entry_delta);

				// inject the delta into the payload starting at the 3rd byte
				*(uint64_t *)(payload_content + 2) = entry_delta;


				file_content = realloc(file_content, file_size + payload_size); // expand the file to fit the payload
				memcpy(file_content + file_size, payload_content, payload_size);

				file_size += payload_size;
				printf("Successfully injected payload\n");
				printf("New entry point: 0x%08lx\n", new_entry_point);

				found_cave = 1;
				break;
			}
		}
	}

	if (!found_cave)
	{
		fprintf(stderr, "Could not find a suitable cave\n");
		free(file_content);
		return EXIT_FAILURE;
	}



	// write the result to a new file
	FILE *new_file = fopen("woody", "w");
	if (new_file == NULL)
	{
		perror("error on fopen");
		free(file_content);
		return EXIT_FAILURE;
	}



	chmod("woody", 0777);

	if (fwrite(file_content, 1, file_size, new_file) != file_size)
	{
		perror("error on fwrite");
		fclose(new_file);
		free(file_content);
		return EXIT_FAILURE;
	}
	

	free(file_content);
}