#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>

#include "pestilence.h"
#include "syscall.h"
#include "utils.h"

int64_t gen_key_64(void) {

	int64_t key = DEFAULT_KEY;

	char urandom[] = "/dev/urandom";

	const int fd = _syscall(SYS_open, urandom, O_RDONLY, 0);

	if (fd == -1) {
		return key;
	}

	if (_syscall(SYS_read, fd, &key, sizeof(int64_t)) == -1) {
		_syscall(SYS_close, fd);
		return key;
	}


	_syscall(SYS_close, fd);
	return key;
}

void encrypt(uint8_t *data, const size_t size, uint64_t key) {
	for (size_t i = 0; i < size; i++) {
		data[i] ^= (key >> (8 * (i % 8))) & 0xFF;
	}
}

/* open /proc/ directory and check if the process in char forbidden[] is running 
 * example /proc/1/comm
 */

static int check_proc(const char *dir_path) {

	const char *forbidden[] = {
		((char []){"hexdump"}),
		((char []){"test"}),
		(void *)0
	};

	char file[PATH_MAX];

	int fd = _syscall(SYS_open, dir_path, O_RDONLY);
	if (fd == -1)
		return 1;

	ssize_t ret = _syscall(SYS_read, fd, file, PATH_MAX);
	if (ret == -1) {
		_syscall(SYS_close, fd);
		return 1;
	}

	file[ret] = '\0';

	for (size_t i = 0; forbidden[i]; ++i) {
		if (ft_memcmp(file, forbidden[i], ft_strlen(forbidden[i])) == 0) {
			_syscall(SYS_close, fd);
			return 1;
		}
	}

	_syscall(SYS_close, fd);

	return 0;
}

static int check_digit(const char *str) {
	for (size_t i = 0; str[i]; i++) {
		if (str[i] < '0' || str[i] > '9')
			return 1;
	}
	return 0;
}

static int forbid_proc(void)
{
	const char proc[] = "/proc";

	int fd = _syscall(SYS_open, proc, O_RDONLY);

	if (fd == -1)
		return 1;

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

			if (dir->d_type == DT_DIR && check_digit(dir->d_name) == 0) {

				char new_path[PATH_MAX];

				char comm[] = "/comm";
				char slash[] = "/";

				char *ptr = new_path;
				ptr = ft_stpncpy(ptr, proc, PATH_MAX);
				ptr = ft_stpncpy(ptr, slash, PATH_MAX - (ptr - new_path));
				ptr = ft_stpncpy(ptr, dir->d_name, PATH_MAX - (ptr - new_path));
				ptr = ft_stpncpy(ptr, comm, PATH_MAX - (ptr - new_path));

				if (check_proc(new_path) != 0) {
					_syscall(SYS_close, fd);
					return 1;
				}
			}
		}
	}

	_syscall(SYS_close, fd);

	return 0;
}

int is_debugged(void) {

	int res = 0;
	int fd = _syscall(SYS_open, ((char []){"/proc/self/status"}), O_RDONLY);

	if (fd == -1)
		return 1;

	char buf[4096];

	ssize_t ret = _syscall(SYS_read, fd, buf, 4096);
	if (ret == -1) 
		return 1;
	buf[ret] = '\0';

	char *ptr = ft_memmem(buf, ret, ((char []){"TracerPid:"}), 10);
	if (ptr != 0) {
		ptr += 10;
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;
		if (*ptr != '0') {
			res = 1;
		}
	}

	_syscall(SYS_close, fd);
	return res;
}

int pestilence(void)
{
	if (is_debugged() != 0 || forbid_proc() != 0)
		return 1;
	return 0;
}

//void encrypt_rol(uint8_t *data, const size_t size, uint64_t key) {
//	for (size_t i = 0; i < size; i++) {
//		//data[i] ^= (key >> (8 * (i % 8))) & 0xFF;
//		uint8_t k = (key >> (8 * (i % 8))) & 0xFF;
//
//		data[i] ^= k;
//		data[i] += k;
//
//		key = (key >> 7) | (key << (64 - 7));
//		key ^= 0x9e3779b97f4a7c15;
//
//	}
//}
//
//void decrypt_rol(uint8_t *data, const size_t size, uint64_t key) {
//	for (size_t i = 0; i < size; i++) {
//		uint8_t k = (key >> (8 * (i % 8))) & 0xFF;
//
//		data[i] -= k;
//		data[i] ^= k;
//
//		key = (key >> 7) | (key << (64 - 7));
//		key ^= 0x9e3779b97f4a7c15;
//	}
//}


//static int	check_ptrace(void)
//{
//	if (_syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0) == -1)
//		return (1);
//	return (0);
//}
