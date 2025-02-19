#ifndef PESTILENCE_H
#define PESTILENCE_H

#include <sys/ptrace.h>
#include <stdint.h>
#include <sys/types.h>


int	check_ptrace(void);
void set_signal_handler(void);
int detect_debugger(void);
void encrypt(uint8_t *data, const size_t size, const uint64_t key);
int gen_key_64(int64_t* key);
#endif
