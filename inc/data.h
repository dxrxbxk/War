#ifndef DATA_H
# define DATA_H

# include <elf.h>
# include <sys/types.h>
# include <stdbool.h>

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

typedef struct s_data {
	uint8_t *file;
	size_t	size;
	Elf64_Off	data_offset;
	size_t data_page_size;

	t_elf	elf;
	t_cave	cave;
	t_packer	packer;
	int64_t	key;
	uint8_t	signature_key;
} t_data;

//int	init_data(t_data *data, uint8_t *file, size_t size);
//int	init_data(t_data *data);
void	free_data(t_data *data);
void	updade_hdr(t_data *data);

#endif
