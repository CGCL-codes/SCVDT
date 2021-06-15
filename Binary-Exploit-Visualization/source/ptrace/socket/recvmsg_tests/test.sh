g++ -o server sudp.cpp
g++ -o client cudp.cpp

gcc -o ptrace ../../ptrace.c

./ptrace ./server
