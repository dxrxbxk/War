#include <sys/mman.h>

#include "utils.h"
#include "syscall.h"
#include "data.h"

void updade_hdr(t_data *data) {
	data->elf.ehdr = (Elf64_Ehdr *)data->file;
	data->elf.phdr = (Elf64_Phdr *)(data->file + data->elf.ehdr->e_phoff);
	data->elf.shdr = (Elf64_Shdr *)(data->file + data->elf.ehdr->e_shoff);
}

void	free_data(t_data *data) {
	if (data->file)
		_syscall(SYS_munmap, data->file, data->size);
}
