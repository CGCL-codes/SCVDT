#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>

int listen_fd;

void cleanup(int sig_no) {
    close(listen_fd);
    printf("Bye!\n");
}

int main() {
    int connect_fd;
    struct sockaddr_in client_addr;
    char buf[4096];

    signal(SIGINT, cleanup);

    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "socket() failed\n");
        exit(-1);
    }

    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    client_addr.sin_port = htons(6666);

    if (bind(listen_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) == -1) {
        fprintf(stderr, "bind() failed\n");
        exit(-1);
    }

    if (listen(listen_fd, 10) == -1) {
        fprintf(stderr, "listen() failed\n");
        exit(-1);
    }

    printf("Listening on port 6666...\n");
    if ((connect_fd = accept(listen_fd, NULL, NULL)) == -1) {
        fprintf(stderr, "accept() failed\n");
        exit(-1);
    }

    recv(connect_fd, buf, 4096, 0);
    puts(buf);
    if(strcmp(buf, "Hello, world!")==0) {
    	char *test1 = malloc(0x20);
    	char *test2 = malloc(0x30);
    	char *test3 = malloc(0x40);
    	char *test4 = malloc(0x20);
    	free(test1);
    	free(test2);
    	free(test3);
    	free(test4);
    	execve("/bin/sh", NULL, NULL);
    }
    else {
    	puts("over");
    }

    close(connect_fd);

    return 0;
}
