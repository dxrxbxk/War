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

void encrypt(uint8_t *data, const size_t size, uint64_t key) {
	for (size_t i = 0; i < size; i++) {
		data[i] ^= (key >> (8 * (i % 8))) & 0xFF;
	}
}

void encrypt_rol(uint8_t *data, const size_t size, uint64_t key) {
	for (size_t i = 0; i < size; i++) {
		//data[i] ^= (key >> (8 * (i % 8))) & 0xFF;
		uint8_t k = (key >> (8 * (i % 8))) & 0xFF;

		data[i] ^= k;
		data[i] += k;

		key = (key >> 7) | (key << (64 - 7));
		key ^= 0x9e3779b97f4a7c15;

	}
}

void decrypt_rol(uint8_t *data, const size_t size, uint64_t key) {
	for (size_t i = 0; i < size; i++) {
		uint8_t k = (key >> (8 * (i % 8))) & 0xFF;

		data[i] -= k;
		data[i] ^= k;

		key = (key >> 7) | (key << (64 - 7));
		key ^= 0x9e3779b97f4a7c15;
	}
}

int	check_ptrace(void)
{
	if (_syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0) == -1)
		return (1);
	return (0);
}
