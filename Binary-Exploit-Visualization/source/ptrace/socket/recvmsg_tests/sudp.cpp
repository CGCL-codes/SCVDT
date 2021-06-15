#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<iostream>

using namespace std;

int main()
{
    int sockfd=::socket(AF_INET,SOCK_DGRAM,0);
    uint16_t port = 23333;
    const char * ip = "127.0.0.1";

    struct sockaddr_in addr;
    addr.sin_family =AF_INET;
    addr.sin_port =htons(port);
    addr.sin_addr.s_addr=inet_addr(ip);
    int ret =::bind(sockfd,(struct sockaddr*)&addr,sizeof(addr));
    if(ret < 0){
        printf("bind error!\n");
        return -1;
    }
    struct sockaddr_in client;
    socklen_t len=sizeof(client);
    while(true){
        msghdr msg;
        msg.msg_name = &client;
        msg.msg_namelen = sizeof(client);
        char buf[1024] = {0};
        struct iovec msg_iov;
        msg_iov.iov_base = buf;
        msg_iov.iov_len = 1024;

        msg.msg_iov = &msg_iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = 0;
        int i = ::recvmsg(sockfd,&msg,0);
        if(i > 0){
            cout << "收到客户端消息:" << string(buf) << endl;
        }
        if(string(buf) == "Bye" || string(buf) == "bye" ){
            break;
        }
    }
    ::close(sockfd);
}
