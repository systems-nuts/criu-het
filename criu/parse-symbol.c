#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <elf.h>
#include <unistd.h>
#include <sys/mman.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>


#define __debug(...) /*pr_info(__VA_ARGS__)*/

//long get_sym_addr(const char* path_to_bin, const char* searched_symbol)
unsigned long get_sym_addr(char* bin_cnt, const char* searched_symbol)
{
/*
	__debug("%s:%d file name %s\n", __func__, __LINE__, path_to_bin);
	FILE *bin_fd = fopen(path_to_bin, "r");
	if (bin_fd == NULL) {
		perror("open file\n");
		goto err;
	}
	__debug("%s:%d\n", __func__, __LINE__);
	if (fseek(bin_fd, 0, SEEK_END)) {
		fclose(bin_fd);
		goto err;
	}
	__debug("%s:%d\n", __func__, __LINE__);
	long bin_size = ftell(bin_fd);

	__debug("%s:%d\n", __func__, __LINE__);
	void *bin_cnt = mmap(NULL, (size_t)bin_size, PROT_READ, MAP_PRIVATE,
			fileno(bin_fd), 0);
	if (bin_cnt == NULL) {
		fclose(bin_fd);
		perror("mmap()");
		goto err;
	}
	fclose(bin_fd);
	__debug("%s:%d\n", __func__, __LINE__);
*/
	Elf64_Ehdr elf_hdr;
	const unsigned char elf_magics[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
	memcpy(&elf_hdr, bin_cnt, sizeof(elf_hdr));
	if (memcmp(elf_hdr.e_ident, elf_magics, sizeof(elf_magics)) != 0) {
		perror("Target is not an ELF executable\n");
		goto err;
	}
	if (elf_hdr.e_ident[EI_CLASS] != ELFCLASS64) {
		perror("Only ELF-64 are supported.\n");
		goto err;
	}
#if 0
	if (elf_hdr.e_machine != EM_X86_64) {
		perror("Sorry, only x86-64 is supported.\n");
		goto err;
	}
#endif

	__debug("file size: %zd\n", bin_size);
	__debug("program header offset: %zd\n", elf_hdr.e_phoff);
	__debug("program header num: %d\n", elf_hdr.e_phnum);
	__debug("section header offset: %zd\n", elf_hdr.e_shoff);
	__debug("section header num: %d\n", elf_hdr.e_shnum);
	__debug("section header string table: %d\n", elf_hdr.e_shstrndx);

	__debug("string offset at %d\n", elf_hdr.e_shstrndx);
	__debug("\n");

	size_t stcsym_off = 0;
	size_t stcsym_sz = 0;
	__attribute__((unused)) size_t dynsym_off = 0;
	__attribute__((unused)) size_t dynsym_sz = 0;
	__attribute__((unused)) size_t strtbl_off = 0;
	__attribute__((unused)) size_t strtbl_sz = 0;

	const char *cbytes = (char *)bin_cnt;
	for (uint16_t i = 0; i < elf_hdr.e_shnum; i++) {
		Elf64_Shdr shdr;
		size_t offset = elf_hdr.e_shoff + i * elf_hdr.e_shentsize;
		memcpy(&shdr, cbytes + offset, sizeof(shdr));
		switch (shdr.sh_type) {
			case SHT_SYMTAB:
				stcsym_off = shdr.sh_offset;
				stcsym_sz = shdr.sh_size;
				__debug("found static symbol table at %zd\n", shdr.sh_offset);
				break;
			case SHT_STRTAB:
				// TODO: have to handle multiple string tables better
				if (!strtbl_off) {
					__debug("found string table at %zd\n", shdr.sh_offset);
					strtbl_off = shdr.sh_offset;
					strtbl_sz = shdr.sh_size;
				}else
					__debug("there are multiple string tables\n");
				break;
			case SHT_DYNSYM:
				dynsym_off = shdr.sh_offset;
				dynsym_sz = shdr.sh_size;
				__debug("found dynsym table at %zd, size %zd\n", shdr.sh_offset,
						shdr.sh_size);
				break;
			default:
				break;
		}
	}

	__debug("final value for dynsym_off = %zd\n", dynsym_off);
	__debug("final value for dynsym_sz = %zd\n", dynsym_sz);
	__debug("final value for stcsym_off = %zd\n", stcsym_off);
	__debug("final value for stcsym_sz = %zd\n", stcsym_sz);
	__debug("final value for strtbl_off = %zd\n", strtbl_off);
	__debug("final value for strtbl_sz = %zd\n", strtbl_sz);

	
	long address=-1;
	for (size_t j = 0; j * sizeof(Elf64_Sym) < stcsym_sz; j++) {
		Elf64_Sym sym;
		const char* name=NULL;
		size_t absoffset = stcsym_off + j * sizeof(Elf64_Sym);
		memcpy(&sym, cbytes + absoffset, sizeof(sym));
		__debug("SYMBOL TABLE ENTRY %zd\n", j);
		__debug("st_name = %d", sym.st_name);
		if (sym.st_name != 0) {
			name = cbytes + strtbl_off + sym.st_name;
			__debug(" (%s)", name); 
		}
		__debug("\n");
		__debug("st_info = %d\n", sym.st_info);
		__debug("st_other = %d\n", sym.st_other);
		__debug("st_shndx = %d\n", sym.st_shndx);
		__debug("st_value = %p\n", (void *)sym.st_value);
		__debug("st_size = %zd\n", sym.st_size);
		__debug("\n");

		if(name && strncmp(searched_symbol, name, strlen(searched_symbol))==0)
		{
			address=sym.st_value;
			break;
		}
	}
	__debug("\n");
	return address;

err:
	return -1;
}

