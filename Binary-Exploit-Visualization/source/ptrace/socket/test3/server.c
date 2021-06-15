#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
    int sockfd, len;
    struct sockaddr_in addr;
    socklen_t addr_len=sizeof(struct sockaddr_in);
    char buffer[256];

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(6666);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    printf("Listening on port 6666...\n");
    recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *) &addr, &addr_len);
    puts(buffer);
    
    close(sockfd);
}