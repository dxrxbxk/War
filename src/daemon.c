#include "daemon.h"
#include "syscall.h"
#include "utils.h"

#include <sys/file.h>

#define CLOSE_END 0
#define NO_CLOSE_END 1

static void logger(const char *msg)
{
	int fd = _syscall(SYS_open, ((char[]){"/tmp/.daemon"}), O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd == -1) {
		return;
	}

	_syscall(SYS_write, fd, msg, ft_strlen(msg));
	_syscall(SYS_close, fd);
}

static int lock(int *lock_fd, int close_end)
{
	*lock_fd = _syscall(SYS_open, ((char[]){"/tmp/.warlock"}), O_CREAT | O_RDWR, 0644);

	if (*lock_fd == -1) {
		return 1;
	}


	if (_syscall(SYS_flock, *lock_fd, LOCK_EX | LOCK_NB) == -1) {
		logger((char []){"already locked\n"});
		_syscall(SYS_close, *lock_fd);
		return 1;
	} else {
		logger((char []){"locked\n"});
	}

	if (close_end == CLOSE_END) {
		_syscall(SYS_close, *lock_fd);
	}

	return 0;
}

static int unlock(int *lock_fd)
{
	//lock_fd = _syscall(SYS_open, ((char[]){"/tmp/.warlock"}), O_RDONLY);

	if (*lock_fd == -1) {
		return 1;
	}
	else if (_syscall(SYS_flock, *lock_fd, LOCK_UN) == -1) {

		logger((char []){"unlock failed\n"});
		_syscall(SYS_close, *lock_fd);
		return 1;
	} else {
		logger((char []){"unlocked\n"});
	}


	_syscall(SYS_close, *lock_fd);
	return 0;
}

void run(int *lock_fd)
{
	struct timespec ts = {5, 0};
	while (1) {


		logger((char []){"daemon is running\n"});

		_syscall(SYS_nanosleep, &ts, 0);

	}

	unlock(lock_fd);
}
//takes a function pointer in argument and calls it
int	daemonize(void)
{
	int lock_fd = -1;
	if (lock(&lock_fd, CLOSE_END) == 1) {
		return 0;
	}

	int		fd;
	pid_t	pid;

	pid = _syscall(SYS_fork);

	if (pid < 0)
		return -1;
	if (pid > 0)
		return 0;

	if (_syscall(SYS_setsid) == -1)
		return -1;

	pid = _syscall(SYS_fork);
	if (pid < 0)
		return -1;
	if (pid > 0)
		_syscall(SYS_exit, 0);

	if (_syscall(SYS_chdir, (char []){"/"}, 0) == -1)
		return -1;

	fd = _syscall(SYS_open, (char []){"/dev/null"}, O_RDONLY);
	if (fd == -1)
		return -1;

	if (_syscall(SYS_dup2, fd, 0) < 0)
		return -1;
	if (_syscall(SYS_dup2, fd, 1) < 0)
		return -1;
	if (_syscall(SYS_dup2, fd, 2) < 0)
		return -1;

	_syscall(SYS_close, fd);

	if (lock(&lock_fd, NO_CLOSE_END) == 1) {
		return 0;
	}

	run(&lock_fd);
	return 0;

}
