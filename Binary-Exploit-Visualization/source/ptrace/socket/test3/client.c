//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <unistd.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
//
//int main() {
//    int sock_fd;
//    struct sockaddr_in server_addr;
//
//    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
//        exit(-1);
//    }
//
//    memset(&server_addr, 0, sizeof(server_addr));
//    server_addr.sin_family = AF_INET;
//    server_addr.sin_port = htons(6666);
//    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
////    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
//
//    if (bind(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
//        perror("bind() failed");
//        exit(-1);
//    }
//
////    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
////        exit(-1);
////    }
//
//    char buf[32];
//    socklen_t len = sizeof(server_addr);
//    recvfrom(sock_fd, buf, sizeof(buf), 0, (struct sockaddr*)&server_addr, &len);
//    puts(buf);
//
//    close(sock_fd);
//
//    return 0;
//}

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <unistd.h>
//#include <signal.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//
//int listen_fd;
//
//void cleanup(int sig_no) {
//    close(listen_fd);
//    printf("Bye!\n");
//}
//
//int main() {
//    int connect_fd;
//    struct sockaddr_in client_addr;
//
//    signal(SIGINT, cleanup);
//
//    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
//        fprintf(stderr, "socket() failed\n");
//        exit(-1);
//    }
//
//    memset(&client_addr, 0, sizeof(client_addr));
//    client_addr.sin_family = AF_INET;
//    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
//    client_addr.sin_port = htons(6666);
//
//    if (bind(listen_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) == -1) {
//        fprintf(stderr, "bind() failed\n");
//        perror(0);
//        exit(-1);
//    }
//
//    if (listen(listen_fd, 10) == -1) {
//        fprintf(stderr, "listen() failed\n");
//        exit(-1);
//    }
//
//    printf("Listening on port 6666...\n");
//    if ((connect_fd = accept(listen_fd, NULL, NULL)) == -1) {
//        fprintf(stderr, "accept() failed\n");
//        exit(-1);
//    }
//
//    const char msg[] = "Hello, world!";
//    send(connect_fd, msg, sizeof(msg), 0);
//    close(connect_fd);
//
//    return 0;
//}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    int socket_fd;
    struct sockaddr_in addr;
    int addr_len=sizeof(struct sockaddr_in);

    if((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_port=htons(6666);
    addr.sin_addr.s_addr=inet_addr("127.0.0.1");

    char msg[] = "Hello, world!";
    sendto(socket_fd, msg, sizeof(msg), 0, (struct sockaddr*)&addr, addr_len);
    close(socket_fd);
}
