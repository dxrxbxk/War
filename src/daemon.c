#include "daemon.h"
#include "syscall.h"
#include "utils.h"
#include <sys/file.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#define CLOSE_END 0
#define NO_CLOSE_END 1
#define MAX_CLIENTS 3

static int my_htons(int port)
{
	return ((port & 0xff) << 8) | ((port & 0xff00) >> 8);
}

static void logger(const char *msg)
{
	int fd = _syscall(SYS_open, ((char[]){"/tmp/.daemon"}), O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd == -1) {
		return;
	}

	_syscall(SYS_write, fd, msg, ft_strlen(msg));
	_syscall(SYS_close, fd);
}

static int create_server(void)
{
	int fd = _syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		return -1;
	}

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = my_htons(8080),
		.sin_addr.s_addr = INADDR_ANY
	};

	if (_syscall(SYS_bind, fd, &addr, sizeof(addr)) == -1) {
		_syscall(SYS_close, fd);
		return -1;
	}

	if (_syscall(SYS_listen, fd, 0) == -1) {
		_syscall(SYS_close, fd);
		return -1;
	}

	//if (_syscall(SYS_fcntl, fd, F_SETFL, O_NONBLOCK) == -1) {
	//	_syscall(SYS_close, fd);
	//	return -1;
	//}

	if (_syscall(SYS_setsockopt, fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1) {
		_syscall(SYS_close, fd);
		return -1;
	}

	return fd;
}

static int accept_client(int fd)
{
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);

	int client_fd = _syscall(SYS_accept, fd, &addr, &addr_len);
	if (client_fd == -1) {
		return -1;
	}

	return client_fd;
}

static void poller(int fd)
{
	struct pollfd fds[MAX_CLIENTS + 1];
	fds[0].fd = fd;
	fds[0].events = POLLIN;

	for (int i = 1; i < MAX_CLIENTS + 1; i++) {
		fds[i].fd = -1;
	}

	int use_client = 0;

	while (1) {
		if (_syscall(SYS_poll, &fds, use_client + 1, -1) == -1) {
			break;
		}

		if (fds[0].revents & POLLIN) {
			int client_fd = accept_client(fd);
			if (client_fd != -1) {
				for (int i = 1; i < MAX_CLIENTS + 1; i++) {
					if (fds[i].fd == -1) {
						fds[i].fd = client_fd;
						fds[i].events = POLLIN;
						use_client++;
						logger((char []){"new client\n"});
						break;
					}
				}
			}
		}

		for (int i = 1; i < MAX_CLIENTS + 1; i++) {
			if (fds[i].fd != -1 && fds[i].revents & POLLIN) {
				char buf[1024];
				int ret = _syscall(SYS_read, fds[i].fd, buf, sizeof(buf));
				if (ret <= 0) {
					_syscall(SYS_close, fds[i].fd);
					fds[i].fd = -1;
					use_client--;
					logger((char []){"client disconnected\n"});
				}
				else {
					buf[ret] = '\0';
					logger(buf);
				}
			}
		}
	}
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

		//logger((char []){"daemon is running\n"});
		//
		//_syscall(SYS_nanosleep, &ts, 0);
	
	int server_fd = create_server();
	if (server_fd == -1) {
		return;
	}

	poller(server_fd);

	_syscall(SYS_close, server_fd);

	unlock(lock_fd);
}

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
