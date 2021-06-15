gcc -o ptrace ../../ptrace.c
gcc -o process ./process.c

./ptrace ./process
