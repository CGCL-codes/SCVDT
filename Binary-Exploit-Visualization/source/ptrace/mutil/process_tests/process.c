#include <stdio.h>
#include <unistd.h>

int main()
{
    pid_t pid;

    pid = fork();
    if (pid == -1) {
        perror("fork error");
        return -1;
    }

    if (pid == 0) {
        printf("child hello!\n");
    } else {
        printf("parent hello!\n");
    }

    return 0;
}