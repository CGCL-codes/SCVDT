gcc ../../ptrace.c -o ./ptrace
gcc ./server.c -o server
gcc ./client.c -o client
LD_BIND_NOW=1 ./ptrace ./server
# strace ./server 
