#ifndef WAR_H
#define WAR_H

#include <stdint.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <limits.h>

#include "data.h"
#include "syscall.h"
#include "utils.h"

#include "pestilence.h"

//int self_name(t_data *data);
int self_name(char *self_name);
//int self_fingerprint(t_data *data);
int self_fingerprint(const char *self_name, size_t increment);
void update_fingerprint(char *fingerprint, t_data *data);

#endif
