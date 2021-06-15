gcc -o ptrace ../../ptrace.c
gcc -o thread ./thread.c -lpthread

./ptrace ./thread
