#include <stdio.h>

int main(int argc, char** argv) {
    char buffer[20];
    for(int i = 1; i < argc; i++){
        printf("%s\t", argv[i]);
    }
    scanf("%20s", buffer);
    puts(buffer);
    getchar();
    fgets(buffer, 20uL, stdin);
    puts(buffer);

    return 0;
}