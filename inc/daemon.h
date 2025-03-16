#ifndef DAEMON_H
#define DAEMON_H

#include <sys/types.h>
#include <fcntl.h>
//#include <signal.h>

int	daemonize(char **envp);

typedef struct param_s {
	int client_fd;
	char **envp;
} param_t;

typedef struct command_s {
	char *name;
	void (*func)(param_t *);
} command_t;


typedef void (*command_func_t)(param_t *);

#endif
