#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#include "pestilence.h"
#include "syscall.h"

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

void encrypt(uint8_t *data, const size_t size, const uint64_t key) {
	for (size_t i = 0; i < size; i++)
		data[i] ^= (key >> (8 * (i % 8))) & 0xFF;
}

void decrypt(uint8_t *data, const size_t size, const uint64_t key) {
	encrypt(data, size, key);
}

int	check_ptrace(void)
{
	if (_syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0) == -1)
	{
		char msg[] = "You can't catch me!\n";
		_syscall(SYS_write, 2, msg, sizeof(msg) - 1, 0);
		return (1);
	}
	return (0);
}
