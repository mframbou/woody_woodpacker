#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <sys/stat.h>
#include <errno.h>

typedef struct s_elffile
{
	unsigned char *content;
	size_t size;
	Elf64_Ehdr *header;
	Elf64_Shdr *section_header_table;
	Elf64_Phdr *program_header_table;
	Elf64_Shdr *shstrtab_section_header;
	size_t _malloc_size;
} t_elffile;

#define ENTRY_DELTA_PAYLOAD_OFFSET 2  				// offset in the payload where the entry delta is stored
#define ENCRYPTION_KEY_PAYLOAD_OFFSET 2+8 			// offset in the payload where the encryption key is stored
#define TEXT_SECTION_SIZE_PAYLOAD_OFFSET 2+8+8 		// offset in the payload where the text section size is stored
#define TEXT_SECTION_DELTA_PAYLOAD_OFFSET 2+8+8+8 	// offset in the payload where the text section delta is stored


unsigned char payload_bin[] = {
	// 0xe9, 0xaa => payload
	// 0xeb, 0x20 => decrypt
  0xeb, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x53,
  0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x56, 0x57, 0x41, 0x56,
  0x41, 0x57, 0x48, 0x8b, 0x05, 0xd9, 0xff, 0xff, 0xff, 0x4c, 0x8b, 0x05,
  0xda, 0xff, 0xff, 0xff, 0x4c, 0x8d, 0x0d, 0xb9, 0xff, 0xff, 0xff, 0x4d,
  0x01, 0xc8, 0x4c, 0x89, 0xc3, 0x48, 0x8b, 0x0d, 0xb6, 0xff, 0xff, 0xff,
  0x48, 0xc7, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x50, 0x53, 0x51, 0x52, 0x49,
  0x89, 0xde, 0x49, 0xc7, 0xc1, 0xff, 0x0f, 0x00, 0x00, 0x49, 0xf7, 0xd1,
  0x4d, 0x21, 0xce, 0x49, 0x89, 0xc7, 0x49, 0x81, 0xc7, 0xff, 0x0f, 0x00,
  0x00, 0x4d, 0x21, 0xcf, 0x4c, 0x89, 0xf7, 0x4c, 0x89, 0xfe, 0x48, 0xc7,
  0xc2, 0x07, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0, 0x0a, 0x00, 0x00, 0x00,
  0x0f, 0x05, 0x5a, 0x59, 0x5b, 0x58, 0x48, 0x39, 0xc2, 0x7d, 0x18, 0x48,
  0x89, 0xdf, 0x48, 0x01, 0xd7, 0x48, 0x0f, 0xb6, 0x37, 0x49, 0x89, 0xc8,
  0x4c, 0x31, 0xc6, 0x40, 0x88, 0x37, 0x48, 0xff, 0xc2, 0xeb, 0xe3, 0x4c,
  0x89, 0xf7, 0x4c, 0x89, 0xfe, 0x48, 0xc7, 0xc2, 0x05, 0x00, 0x00, 0x00,
  0x48, 0xc7, 0xc0, 0x0a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x41, 0x5f, 0x41,
  0x5e, 0x5f, 0x5e, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x5a, 0x59, 0x5b,
  0x58, 0xeb, 0x0e, 0x2e, 0x2e, 0x2e, 0x2e, 0x57, 0x4f, 0x4f, 0x44, 0x59,
  0x2e, 0x2e, 0x2e, 0x2e, 0x0a, 0x57, 0x56, 0x52, 0x50, 0x48, 0xc7, 0xc7,
  0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x35, 0xe0, 0xff, 0xff, 0xff, 0x48,
  0xc7, 0xc2, 0x0e, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00,
  0x00, 0x0f, 0x05, 0x48, 0x8b, 0x05, 0xf0, 0xfe, 0xff, 0xff, 0x4c, 0x8d,
  0x15, 0xe7, 0xfe, 0xff, 0xff, 0x49, 0x29, 0xc2, 0x58, 0x5a, 0x5e, 0x5f,
  0x41, 0xff, 0xe2
};
uint64_t payload_size = 291;

unsigned char encryption_key = 0x42;

// https://tmpout.sh/1/2.html
// https://www.symbolcrash.com/2019/03/27/pt_note-to-pt_load-injection-in-elf/
// https://github.com/zznop/drow

void encrypt(void *addr, size_t size, unsigned char key)
{
	// simple XOR encryption

	for (size_t i = 0; i < size; i++)
	{
		((unsigned char *)addr)[i] ^= key;
	}
}

Elf64_Shdr *find_section_by_name(t_elffile *elffile, const char *section_name)
{
	for (size_t i = 0; i < elffile->header->e_shnum; i++)
	{
		if (strcmp((char *)(elffile->content + elffile->shstrtab_section_header->sh_offset + elffile->section_header_table[i].sh_name), section_name) == 0)
			return &(elffile->section_header_table[i]);
	}
	return NULL;
}

Elf64_Phdr *find_segment_of_section(t_elffile *elffile, Elf64_Shdr *section)
{
	for (size_t i = 0; i < elffile->header->e_phnum; i++)
	{
		if (elffile->program_header_table[i].p_offset <= section->sh_offset && elffile->program_header_table[i].p_offset + elffile->program_header_table[i].p_filesz >= section->sh_offset + section->sh_size)
			return &(elffile->program_header_table[i]);
	}
	return NULL;
}

mode_t get_file_mode(const char *filename)
{
	struct stat sb;
	if (stat(filename, &sb) == -1)
	{
		perror("stat");
		return 0;
	}
	return sb.st_mode;
}

int encrypt_section(t_elffile *elffile, const char *section_name, unsigned char key)
{
	Elf64_Shdr *section = find_section_by_name(elffile, section_name);
	if (section == NULL)
	{
		fprintf(stderr, "Could not find section %s\n", section_name);
		return 1;
	}
	printf("INFO: encrypting section %s of size %ld bytes\n", section_name, section->sh_size);
	printf("section start: %08lx, section end: %08lx\n", section->sh_offset, section->sh_offset + section->sh_size);
	encrypt(elffile->content + section->sh_offset, section->sh_size, key);
	return 0;
}

// set some data into a payload at a specific offset
// data_size is the size in bytes of the data to inject (eg uint64_t = 8 bytes)
int set_payload_data(unsigned char *payload, size_t payload_size, void *data, size_t data_size, size_t offset)
{
	if (offset + data_size > payload_size)
	{
		fprintf(stderr, "Cannot set data at offset %ld, not enough space in the payload\n", offset);
		return 1;
	}
	memcpy(payload + offset, data, data_size);
	return 0;
}

void expand_segment_section(t_elffile *elffile, Elf64_Phdr *segment, Elf64_Shdr *section, size_t expand_by)
{
	if (segment != NULL)
	{
		segment->p_memsz += expand_by;
		segment->p_filesz += expand_by;
	}
	
	if (section != NULL)
	{
		section->sh_size += expand_by;
	}
}

void patch_payload_entry(unsigned char *payload, size_t payload_size, t_elffile *elffile, uint64_t new_entry_point)
{
	uint64_t old_entry_point = elffile->header->e_entry;
	elffile->header->e_entry = new_entry_point;

	int64_t entry_delta = 0;
	// avoid overflow
	if (new_entry_point > old_entry_point)
		entry_delta = new_entry_point - old_entry_point;
	else
		entry_delta = -(int64_t)(old_entry_point - new_entry_point);

	set_payload_data(payload, payload_size, &entry_delta, sizeof(entry_delta), ENTRY_DELTA_PAYLOAD_OFFSET);
}

void patch_payload_decrypt_offset(unsigned char *payload, size_t payload_size, t_elffile *elffile, uint64_t payload_vaddr)
{
	Elf64_Shdr *text_section = find_section_by_name(elffile, ".text");
	if (text_section == NULL)
	{
		fprintf(stderr, "woodpacker: could not find .text section, this should never happen\n");
		return;
	}

	Elf64_Phdr *text_segment = find_segment_of_section(elffile, text_section);
	if (text_segment == NULL)
	{
		fprintf(stderr, "woodpacker: could not find segment of .text section, this should never happen\n");
		return;
	}

	// vaddr of segment + offset of section in segment
	uint64_t text_section_vaddr = text_segment->p_vaddr + (text_section->sh_offset - text_segment->p_offset);
	int64_t text_section_delta = 0;
	// avoid overflow
	if (payload_vaddr > text_section_vaddr)
		text_section_delta = -(int64_t)(payload_vaddr - text_section_vaddr);
	else
		text_section_delta = text_section_vaddr - payload_vaddr;

	set_payload_data(payload, payload_size, &text_section_delta, sizeof(text_section_delta), TEXT_SECTION_DELTA_PAYLOAD_OFFSET);
}

int inject_payload(t_elffile *elffile, unsigned char *payload, size_t payload_size, void *payload_start)
{
	if (payload_start < (void *)elffile->content || payload_start > ((void *)elffile->content + elffile->size))
	{
		fprintf(stderr, "woodpacker: invalid payload start address\n");
		return 1;
	}

	memcpy(payload_start, payload, payload_size);
	return 0;
}

void expand_file(t_elffile *elffile, size_t expand_by)
{
	if (elffile->size + expand_by > elffile->_malloc_size)
	{
		// realloc and update pointers
		printf("INFO: expanding file (realloc) by %ld bytes\n", expand_by);
		void *new_content = realloc(elffile->content, elffile->size + expand_by);
		if (new_content == NULL)
		{
			perror("woodpacker: realloc error");
			exit(EXIT_FAILURE);
		}
		free(elffile->content);
		elffile->content = new_content;
		elffile->_malloc_size = elffile->size + expand_by;

		elffile->header = (Elf64_Ehdr *)elffile->content;
		elffile->program_header_table = (Elf64_Phdr *)(elffile->content + elffile->header->e_phoff);
		elffile->section_header_table = (Elf64_Shdr *)(elffile->content + elffile->header->e_shoff);
		elffile->shstrtab_section_header = elffile->section_header_table + elffile->header->e_shstrndx;
		elffile->size += expand_by;
	}
	else
	{
		// we have enough space, just update size
		printf("INFO: expanding file by %ld bytes\n", expand_by);
		elffile->size += expand_by;
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

// Opens and parses an ELF file, returns 1 on error
int parse_elf_file(const char *filename, t_elffile *elffile)
{
	memset(elffile, 0, sizeof(t_elffile));

	int fd = open(filename, O_RDONLY);
	if (fd == -1)
	{
		fprintf(stderr, "woodpacker: cannot open file %s: %s\n", filename, strerror(errno));
		return 1;
	}

	elffile->size = lseek(fd, 0, SEEK_END);
	if (elffile->size == -1)
	{
		perror("woodpacker: lseek END error");
		return 1;
	}
	
	// malloc instead of mmap in case we want to call woody on woody
	elffile->content = malloc(elffile->size + payload_size); // in case we need to expand the file, so we dont need to realloc and invalidate pointers
	elffile->_malloc_size = elffile->size + payload_size;
	if (elffile->content == NULL)
	{
		perror("woodpacker: malloc error");
		return 1;
	}

	if (lseek(fd, 0, SEEK_SET) == -1)
	{
		perror("woodpacker: lseek SET error");
		return 1;
	}

	if (read(fd, elffile->content, elffile->size) == -1)
	{
		fprintf(stderr, "woodpacker: cannot read file %s: %s\n", filename, strerror(errno));
		return 1;
	}

	if (close(fd == -1))
	{
		perror("woodpacker: close error");
		return 1;
	}

	if (elffile->size < EI_NIDENT) // If we cannot get identification infos (magic number, architecture etc.)
	{
		fprintf(stderr, "woodpacker: file %s is too small to be an ELF file\n", filename);
		return 1;
	}

	if (!is_elf_file(elffile->content, elffile->size))
	{
		fprintf(stderr, "woodpacker: file %s is not an ELF file\n", filename);
		return 1;
	}

	if (elffile->content[EI_VERSION] != EV_CURRENT)
	{
		fprintf(stderr, "woodpacker: file %s has invalid ELF version\n", filename);
		return 1;
	}

	if (elffile->content[EI_CLASS] != ELFCLASS64)
	{
		fprintf(stderr, "woodpacker: file %s is not a 64-bit ELF file\n", filename);
		return 1;
	}

	if (elffile->size < sizeof(Elf64_Ehdr))
	{
		fprintf(stderr, "woodpacker: file %s is truncated\n", filename);
		return 1;
	}

	elffile->header = (Elf64_Ehdr *)elffile->content;

	// check if section header table is within the file (header section start + header section size * header section entries count)
	if (elffile->content + elffile->header->e_shoff + (elffile->header->e_shentsize * elffile->header->e_shnum) > elffile->content + elffile->size)
	{
		fprintf(stderr, "woodpacker: invalid section header table\n");
		return 1;
	}

	// if shstrtab section index is invalid
	if (elffile->header->e_shstrndx >= elffile->header->e_shnum)
	{
		fprintf(stderr, "woodpacker: invalid shstrtab section index\n");
		return 1;
	}

	elffile->section_header_table = (Elf64_Shdr *)(elffile->content + elffile->header->e_shoff);
	elffile->shstrtab_section_header = elffile->section_header_table + elffile->header->e_shstrndx;
	elffile->program_header_table = (Elf64_Phdr *)(elffile->content + elffile->header->e_phoff);

	if (elffile->shstrtab_section_header->sh_type != SHT_STRTAB)
	{
		fprintf(stderr, "woodpacker: invalid shstrtab section type\n");
		return 1;
	}

	if (elffile->shstrtab_section_header->sh_offset + elffile->shstrtab_section_header->sh_size > elffile->size)
	{
		fprintf(stderr, "woodpacker: invalid shstrtab section size\n");
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		usage();
		return EXIT_FAILURE;
	}

	t_elffile elffile = {0};

	if (parse_elf_file(argv[1], &elffile) != 0)
	{
		free(elffile.content);
		return EXIT_FAILURE;
	}

	if (encrypt_section(&elffile, ".text", encryption_key) != 0)
	{
		free(elffile.content);
		return EXIT_FAILURE;
	}

	// inject decryption key into payload
	if (set_payload_data(payload_bin, payload_size, &encryption_key, sizeof(encryption_key), ENCRYPTION_KEY_PAYLOAD_OFFSET) != 0)
	{
		free(elffile.content);
		return EXIT_FAILURE;
	}

	Elf64_Shdr *text_section = find_section_by_name(&elffile, ".text");
	if (text_section == NULL)
	{
		fprintf(stderr, "woodpacker: could not find .text section\n");
		free(elffile.content);
		return EXIT_FAILURE;
	}

	// inject text decrypt section size into payload
	if (set_payload_data(payload_bin, payload_size, &(text_section->sh_size), sizeof(text_section->sh_size), TEXT_SECTION_SIZE_PAYLOAD_OFFSET) != 0)
	{
		free(elffile.content);
		return EXIT_FAILURE;
	}

	// find segment where .text section is located
	Elf64_Phdr *text_segment = find_segment_of_section(&elffile, text_section);
	
	if (text_segment == NULL)
	{
		fprintf(stderr, "woodpacker: could not find segment of .text section\n");
		free(elffile.content);
		return EXIT_FAILURE;
	}

	// printf("Encrypted .text section\n");
	
	int injected_payload = 0;
	// Elf64_Shdr *section_header_table = (Elf64_Shdr *)(elffile.content + header->e_shoff);
	// We find an executable segment, find the last section in this segment, then try to expand it using the free padding space, try this for every executable segment
	for (size_t i = 0; i < elffile.header->e_phnum; i++)
	{
		if (injected_payload)
			break;

		Elf64_Phdr *current_segment = &(elffile.program_header_table[i]);
		// only interested in executable segments that are loaded in memory
		if (current_segment->p_type != PT_LOAD || !(current_segment->p_flags & PF_X))
			continue;

		current_segment->p_flags = PF_X | PF_R | PF_W;

		printf("INFO: exec segment from 0x%08lx to 0x%08lx (size: %ld bytes)\n", current_segment->p_offset, (current_segment->p_offset + current_segment->p_memsz), current_segment->p_memsz);
		uint64_t segment_start = current_segment->p_offset;
		uint64_t segment_end = current_segment->p_offset + current_segment->p_memsz; // memsz instead of filesz for .bss section for instance

		for (size_t j = 0; j < elffile.header->e_shnum; j++)
		{
			Elf64_Shdr *current_section = &(elffile.section_header_table[j]);

			uint64_t section_start = current_section->sh_offset;
			uint64_t section_end = current_section->sh_offset + current_section->sh_size;

			// last section in the segment
			if (section_end == segment_end)
			{
				uint64_t next_section_start = -1; // default value if its the last section
				if (j < elffile.header->e_shnum - 1)
				{
					// not last section of the file
					next_section_start = elffile.section_header_table[j + 1].sh_offset;
				}

				uint64_t available_space = next_section_start - section_end;
				if (available_space < payload_size)
				{
					printf("INFO: not enough space for the payload, trying next section\n");
					continue;
				}

				printf("INFO: found %ld bytes of free space at address 0x%08lx (payload size: %ld)\n", available_space, section_end, payload_size);

				void *payload_start = elffile.content + section_end;
				uint64_t new_entry_point = section_end;

				// now we expand the section and segment to fit the payload
				uint64_t payload_vaddr = current_segment->p_vaddr + current_segment->p_memsz; // vaddr where the payload will be loaded
				expand_segment_section(&elffile, current_segment, current_section, payload_size);
				printf("INFO: old entry point: 0x%08lx\n", elffile.header->e_entry);
				printf("INFO: new entry point: 0x%08lx\n", new_entry_point);
				patch_payload_entry(payload_bin, payload_size, &elffile, new_entry_point);
				patch_payload_decrypt_offset(payload_bin, payload_size, &elffile, payload_vaddr);

				if (inject_payload(&elffile, payload_bin, payload_size, payload_start) != 0)
				{
					free(elffile.content);
					return EXIT_FAILURE;
				}

				injected_payload = 1;
				break;
			}
		}

		if (!injected_payload)
		{
			printf("INFO: couldn't find code cave in current segment, try to expand the segment\n");
			
			// We check if the segment has the highest virtual address (last segment in memory) meaning we can expand it without overlapping other segments
			// Also check if we can expand the segment in file without overlapping other sections (eg if code is injected at the end of the file it's good)
			Elf64_Phdr *highest_vaddr_segment = NULL;
			for (size_t i = 0; i < elffile.header->e_phnum; i++)
			{
				if (current_segment->p_type == PT_LOAD)
				{
					if (highest_vaddr_segment == NULL || current_segment->p_vaddr > highest_vaddr_segment->p_vaddr)
						highest_vaddr_segment = current_segment;
				}
			}

			if (current_segment != highest_vaddr_segment)
			{
				printf("INFO: segment is not the highest virtual address PT_LOAD segment, continue searching for cave\n");
				continue;
			}

			uint64_t segment_end_offset = current_segment->p_offset + current_segment->p_memsz; // memsz instead of filesz because we don't want to risk touching uninitialized data (eg .bss) even if it should work
			uint64_t segment_new_end_offset = segment_end + payload_size;

			int overlaps = 0;
			for (size_t j = 0; j < elffile.header->e_phnum; j++)
			{
				Elf64_Phdr *overlapping_segment = &(elffile.program_header_table[j]);
				// we use filesz and not memsz because we just want to see if we can expand in file. There might be overlap when loaded in memory but we don't care (since our code is executed first)
				// for instance with .bss section, which is probably loaded in same memory space as the segment but we don't care
				if (segment_new_end_offset > overlapping_segment->p_offset && segment_new_end_offset < overlapping_segment->p_offset + overlapping_segment->p_filesz)
				{
					overlaps = 1;
					break;
				}
			}

			if (overlaps)
			{
				printf("INFO: segment overlaps other segment in file, cannot expand\n");
				continue;
			}

			// We can now expand the segment
			printf("INFO: expanding segment at %08lx by %ld bytes, new entry: 0x%08lx\n", current_segment->p_offset, payload_size, current_segment->p_vaddr + current_segment->p_memsz);
			patch_payload_entry(payload_bin, payload_size, &elffile, current_segment->p_vaddr + current_segment->p_memsz); // new entry point is end of the segment before expansion
			patch_payload_decrypt_offset(payload_bin, payload_size, &elffile, current_segment->p_vaddr + current_segment->p_memsz); // update text section decrypt offset
			expand_segment_section(&elffile, current_segment, NULL, payload_size); // we don't care about the section, we just want to expand the segment
			expand_file(&elffile, payload_size);
			if (inject_payload(&elffile, payload_bin, payload_size, elffile.content + elffile.size - payload_size) != 0)
			{
				free(elffile.content);
				return EXIT_FAILURE;
			}

			printf("INFO: successfully expanded segment by %ld bytes\n", payload_size);
			injected_payload = 1;
			break;
		}
	}

	if (!injected_payload)
	{
		printf("INFO: couldn't find nor expand code cave in any segment, trying PT_NOTE injection\n");

		// find the highest virtual address in use
		uint64_t highest_vaddr = 0;
		for (size_t i = 0; i < elffile.header->e_phnum; i++)
		{
			if (elffile.program_header_table[i].p_vaddr + elffile.program_header_table[i].p_memsz > highest_vaddr)
				highest_vaddr = elffile.program_header_table[i].p_vaddr + elffile.program_header_table[i].p_memsz;
		}

		highest_vaddr = (highest_vaddr + 0xfff) & ~0xfff; // align to page size
		printf("INFO: highest virtual address: 0x%08lx\n", highest_vaddr);

		for (size_t i = 0; i < elffile.header->e_phnum; i++)
		{
			Elf64_Phdr *segment = &(elffile.program_header_table[i]);

			if (segment->p_type != PT_NOTE)
				continue;

			printf("INFO: found PT_NOTE segment\n");

			// we now modify the PT_NOTE segment to be a PT_LOAD segment, setting right permissions, virtual address and size
			// we then inject the payload at the end of the file and set the entry point to the new virtual address

			segment->p_type = PT_LOAD;
			segment->p_flags = PF_R | PF_X;
			// segment->p_align = 0x1000;

			// we don't care about previous content of segment, we just overwrite it
			segment->p_filesz = payload_size;
			segment->p_memsz = payload_size;
			segment->p_align = 0x1000;

			segment->p_vaddr = highest_vaddr; // + elffile.size; // why is this + elffile.size mandatory ?? prob for alignment but why ?? (otherwise segfault)
			uint64_t aligned_offset = (elffile.size + 0xfff) & ~0xfff;
			segment->p_offset = aligned_offset;
			// segment->p_offset = elffile.size; // append the payload to the end of the file

			uint64_t new_entry_point = segment->p_vaddr;
			patch_payload_entry(payload_bin, payload_size, &elffile, new_entry_point);
			patch_payload_decrypt_offset(payload_bin, payload_size, &elffile, segment->p_vaddr);

			uint64_t new_file_size = aligned_offset + payload_size;
			elffile.content = realloc(elffile.content, new_file_size);
			elffile.size = new_file_size;
			elffile._malloc_size = new_file_size;
			// expand_file(&elffile, payload_size);
			printf("test: %08lx %08lx %08lx\n", elffile.size, aligned_offset, payload_size);
			if (inject_payload(&elffile, payload_bin, payload_size, elffile.content + segment->p_offset) != 0)
			{
				free(elffile.content);
				return EXIT_FAILURE;
			}

			injected_payload = 1;
			break;
		}
	}

	if (!injected_payload)
	{
		fprintf(stderr, "woodpacker: couldn't find a way to inject payload\n");
		free(elffile.content);
		return EXIT_FAILURE;
	}

	FILE *out_file = fopen("woody", "w");
	if (out_file == NULL)
	{
		perror("woodpacker: error on fopen output file");
		free(elffile.content);
		return EXIT_FAILURE;
	}


	mode_t original_mode = get_file_mode(argv[1]);
	chmod("woody", original_mode);

	if (fwrite(elffile.content, 1, elffile.size, out_file) != elffile.size)
	{
		perror("woodpacker: error on fwrite output file");
		fclose(out_file);
		free(elffile.content);
		return EXIT_FAILURE;
	}
	
	fclose(out_file);
	free(elffile.content);
	printf("INFO: successfully injected payload\n");

	return EXIT_SUCCESS;
}