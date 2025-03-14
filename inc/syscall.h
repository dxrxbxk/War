#ifndef SYSCALL_H
# define SYSCALL_H

# include <sys/syscall.h>

extern long _syscall(long number, ...);

# define write(_fd, _ptr, _size) (_syscall(SYS_write, (_fd), (_ptr), (_size)))
# define close(_fd) (_syscall(SYS_close, (_fd)))
# define pread(_fd, _buf, _count, _offset) (_syscall(SYS_pread64, (_fd), (_buf), (_count), (_offset)))
# define open(_filename, _args...) (_syscall(SYS_open, _filename, _args))
# define munmap(_addr, _length) (_syscall(SYS_munmap, (_addr), (_length)))
# define mmap(_addr, _length, _prot, _flags, _fd, _offset) (_syscall(SYS_mmap, (_addr), (_length), (_prot), (_flags), (_fd), (_offset)))
# define flock(_fd, _op) (_syscall(SYS_flock, (_fd), (_op)))
# define fstat(_fd, _statbuf) (_syscall(SYS_fstat, (_fd), (_statbuf)))
# define nanosleep(_duration, _rem) (_syscall(SYS_nanosleep, (_duration), (_rem))) 
# define ftruncate(_fd, _length) (_syscall(SYS_ftruncate, (_fd), (_length)))
# define read(_fd, _buf, _count) (_syscall(SYS_read, (_fd), (_buf), (_count)))
# define dup2(_oldfd, _newfd) (_syscall(SYS_dup2, (_oldfd), (_newfd)))
# define fork() (_syscall(SYS_fork))
# define exit(_status) (_syscall(SYS_exit, (_status)))
# define unlink(_pathname) (_syscall(SYS_unlink, (_pathname)))
# define getdents64(_fd, _dirp, _count) (_syscall(SYS_getdents64, (_fd), (_dirp), (_count)))
# define ptrace(_op, _pid, _addr, _data) (_syscall(SYS_ptrace, (_op), (_pid), (_addr), (_data)))
# define setsid() (_syscall(SYS_setsid))
# define readlink(_pathname, _buf, _bufsiz) (_syscall(SYS_readlink, (_pathname), (_buf), (_bufsiz)))
# define chdir(_path) (_syscall(SYS_chdir, (_path)))
# define execve(_pathname, _argv, _envp) (_syscall(SYS_execve, (_pathname), (_argv), (_envp)))
# define wait4(_pid, _wstatus, _options, _rusage) (_syscall(SYS_wait4, (_pid), (_wstatus), (_options)))
# define socket(_domain, _type, _protocol) (_syscall(SYS_socket, (_domain), (_type), (_protocol)))
# define bind(_sockfd, _addr, _addrlen) (_syscall(SYS_bind, (_sockfd), (_addr), (_addrlen)))
# define listen(_sockfd, _backlog) (_syscall(SYS_listen, (_sockfd), (_backlog)))
# define fcntl(_fd, _args...) (_syscall(SYS_fcntl, (_fd), _args))
# define setsockopt(_sockfd, _level, _optname, _optval, _optlen) (_syscall(SYS_setsockopt, (_sockfd), (_level), (_optname), (_optval), (_optlen)))
# define accept(_sockfd, _addr, _addrlen) (_syscall(SYS_accept, (_sockfd), (_addr), (_addrlen)))
# define poll(_fds, _nfds, _timeout) (_syscall(SYS_poll, (_fds), (_nfds), (_timeout)))

# define STR(_str) ((char[]){_str})

#endif
