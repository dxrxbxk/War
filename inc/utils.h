#ifndef UTILS_H
# define UTILS_H

# include <stdint.h>
# include <sys/types.h>

# include "data.h"

//void modify_payload(int64_t value, size_t offset, size_t size, uint8_t *payload, size_t payload_size);
int		ft_strlen(const char *s);
void	*ft_memset(void *b, int c, size_t len);
void	*ft_memcpy(void *dst, const void *src, size_t size);
void	ft_memmove(void *dst, const void *src, size_t size);
int		ft_memcmp(const void *s1, const void *s2, size_t size);
void	ft_strcpy(char *dest, const char *src);
size_t	ft_strlcat(char *dst, const char *src, size_t size);
void	make_path(char *path, const char *dir, const char *file);
void *ft_strnstr(const char *haystack, const char *needle, size_t len);
void *ft_memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len);
uint32_t* bswap32(uint32_t *x);
uint64_t* bswap64(uint64_t *x);
void *search_signature(t_data *data, const char *key);
void	ft_strlcpy(char *dst, const char *src, size_t size);

size_t ft_memindex(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len);
#endif
