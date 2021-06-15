## system calls

| System call number | System call name | memory modified | memory recorded                    |
| ------------------ | ---------------- | --------------- | ---------------------------------- |
| 0                  | read             | Yes             | buffer                             |
| 2                  | open             | No              | —                                  |
| 3                  | close            | No              | —                                  |
| 4                  | stat             | Yes             | stat struct                        |
| 5                  | fstat            | Yes             | stat struct                        |
| 6                  | lstat            | Yes             | stat struct                        |
| 7                  | poll             | Yes             | pollfd struct                      |
| 9                  | mmap             | Yes             | memory's segment modified          |
| 12                 | brk              | No              | —                                  |
| 16                 | ioctl            | Yes             | handle according to request opcode |
| 23                 | select           | Yes             | fd_set、timeval struct             |
| 41                 | socket           | No              | —                                  |
| 42                 | connect          | No              | —                                  |
| 43                 | accept           | No              | —                                  |
| 45                 | recvfrom         | Yes             | buffer、sockaddr、socklen_t struct |
| 47                 | recvmsg          | Yes             | msghdr struct                      |
| 55                 | getsockopt       | Yes             | socklen_t struct                   |
| 100                | times            | Yes             | tms struct                         |
| 111                | getpgrp          | No              | —                                  |
| 318                | getrandom        | Yes             | buffer                             |

