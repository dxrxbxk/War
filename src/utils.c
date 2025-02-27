#include "utils.h"
#include <string.h>

int	ft_strlen(const char *s)
{
	int i = 0;
	while (s[i])
		i++;
	return (i);
}

void	*ft_memset(void *b, int c, size_t len) {
	uint8_t *ptr = b;
	for (size_t i = 0; i < len; i++) {
		ptr[i] = c;
	}
	return b;
}

void	*ft_memcpy(void *dst, const void *src, size_t size) {
	uint8_t *d = dst;
	uint8_t *s = (uint8_t *)src;

	for (size_t i = 0; i < size; i++) {
		d[i] = s[i];
	}
	return dst;
}

size_t	ft_strncmp(const char *s1, const char *s2, size_t n) {
	for (size_t i = 0; i < n; i++) {
		if (s1[i] != s2[i])
			return (s1[i] - s2[i]);
		if (s1[i] == '\0')
			return 0;
	}
	return 0;
}

void *ft_strnstr(const char *haystack, const char *needle, size_t len) {
	size_t needle_len = ft_strlen(needle);
	if (needle_len == 0)
		return (char *)haystack;
	for (size_t i = 0; i < len; i++) {
		if (haystack[i] == needle[0]) {
			if (ft_strncmp(haystack + i, needle, needle_len) == 0)
				return (char *)haystack + i;
		}
	}
	return NULL;
}

void	ft_memmove(void *dst, const void *src, size_t size) {
	uint8_t *d = dst;
	uint8_t *s = (uint8_t *)src;

	if (d < s) {
		for (size_t i = 0; i < size; i++) {
			d[i] = s[i];
		}
	} else {
		for (size_t i = size; i > 0; i--) {
			d[i - 1] = s[i - 1];
		}
	}
}

int	ft_memcmp(const void *s1, const void *s2, size_t size) {
	uint8_t *str1 = (uint8_t *)s1;
	uint8_t *str2 = (uint8_t *)s2;

	for (size_t i = 0; i < size; i++) {
		if (str1[i] != str2[i])
			return (str1[i] - str2[i]);
	}
	return (0);
}

size_t ft_memindex(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) {
    if (!haystack || !needle || needle_len == 0 || haystack_len < needle_len) {
        return 0;
    }

    const unsigned char *h = (const unsigned char *)haystack;
    const unsigned char *n = (const unsigned char *)needle;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (h[i] == n[0] && ft_memcmp(&h[i], n, needle_len) == 0) {
			return i;
        }
    }
    return 0;
}
void *ft_memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) {
    if (!haystack || !needle || needle_len == 0 || haystack_len < needle_len) {
        return NULL;
    }

    const unsigned char *h = (const unsigned char *)haystack;
    const unsigned char *n = (const unsigned char *)needle;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (h[i] == n[0] && ft_memcmp(&h[i], n, needle_len) == 0) {
            return (void *)&h[i];
        }
    }
    return NULL;
}

void	ft_strcpy(char *dest, const char *src)
{
	int i = 0;
	while (src[i])
	{
		dest[i] = src[i];
		i++;
	}
	dest[i] = '\0';
}

void	ft_strlcpy(char *dst, const char *src, size_t size)
{
	size_t i = 0;
	while (src[i] && i + 1 < size)
	{
		dst[i] = src[i];
		i++;
	}
	if (i < size)
		dst[i] = '\0';
}

size_t ft_strlcat(char *dst, const char *src, size_t size)
{
	size_t i = 0;
	size_t j = 0;
	size_t len = 0;
	while (dst[i] && i < size)
		i++;
	len = i;
	while (src[j] && i + 1 < size)
	{
		dst[i] = src[j];
		i++;
		j++;
	}
	if (len < size)
		dst[i] = '\0';
	return (len + ft_strlen(src));
}

void	make_path(char *path, const char *dir, const char *file)
{
	char slash[] = "/";
	ft_strcpy(path, dir);
	ft_strlcat(path, slash, PATH_MAX);
	ft_strlcat(path, file, PATH_MAX);
}

uint32_t* bswap32(uint32_t *x) {
	*x = (*x >> 24) | 
		((*x << 8) & 0x00FF0000) |
		((*x >> 8) & 0x0000FF00) |
		(*x << 24);
	return x;
}

uint64_t* bswap64(uint64_t *x) {
	*x = (*x >> 56) | 
		((*x << 40) & 0x00FF000000000000) |
		((*x << 24) & 0x0000FF0000000000) |
		((*x << 8) & 0x000000FF00000000) |
		((*x >> 8) & 0x00000000FF000000) |
		((*x >> 24) & 0x0000000000FF0000) |
		((*x >> 40) & 0x000000000000FF00) |
		(*x << 56);
	return x;
}

void modify_sign(uint8_t *data, size_t size, uint32_t key) {
	//char msg[] = "modify_sign\n";
	//_syscall(SYS_write, 2, msg, sizeof(msg));
	//_syscall(SYS_write, 2, data, 4);
	//char msg2[] = "\n";
	//_syscall(SYS_write, 2, msg2, sizeof(msg2));

	uint64_t tmp = *(uint64_t *)data;
	bswap64(&tmp);
	tmp ^= key;
	bswap64(&tmp);
	*(uint64_t *)data = tmp;
}

void modify_sign_key(uint8_t *data, size_t size, uint8_t key) {
	for (size_t i = 0; i < size; i++)
		data[i] += key;
}

void *search_signature(t_data *data, const char *key) {
	if (!data || !data->file || !key) {
		return NULL;
    }

    size_t key_len = ft_strlen(key);
    if (key_len == 0 || key_len > data->size) {
		return NULL;
    }

    void *found = ft_memmem(data->file, data->size, key, key_len);
    return found;
}

//static int64_t get_key(t_data *data) {
//	size_t key_offset = (size_t)&key - (size_t)&packer_start;
//
//	Elf64_Ehdr *ehdr = data->elf.ehdr;
//	Elf64_Phdr *phdr = data->elf.phdr;
//	int64_t key = 0;
//
//	for (size_t i = 0; i < ehdr->e_phnum; ++i) {
//		if (phdr[i].p_type != PT_LOAD || (phdr[i].p_flags & PF_X) == 0)
//			continue;
//
//		key = *(int64_t *)(data->file + phdr[i].p_offset + key_offset);
//		break;
//	}
//
//	return key;
//}
//
//
//uint32_t sign_key_val = *(uint32_t*)(data->file + data->packer.offset + sign_key_offset);
//
//
//uint8_t *sign = data->file + data->packer.offset + sign_offset + SIGN_NUM_OFF;
//modify_sign(sign, 8, sign_key_val);
//sign_key_val = sign_key_val + 1;
//
//ft_memcpy(data->file + data->packer.offset + sign_key_offset, (uint32_t *)&sign_key_val, sizeof(uint32_t));
