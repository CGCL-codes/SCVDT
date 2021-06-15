//# mistake.c
//# gcc mistake.c -z execstack -o mistake
#include <stdio.h>
#include <stdlib.h>

typedef struct chunk{
    char buffer[0x10];
    int len;
}chunk;

chunk* list[0x30];
int chunk_number;

void menu()
{
    write(1,"1.create\n",9);
    write(1,"2.read\n",7);
    write(1,"3.free\n",7);
    write(1,"4.bye\n",6);
    write(1,"> ",2);
}

int transfer(char* buffer){
    int i,result = 0;
    for(i = 0;*(buffer+i) != 0;i++){
        if(*(buffer+i) > '9'||*(buffer+i) < '0'){
            return -1;
        }
        result = result*10 - '0' + *(buffer+i);
    }
    return result;
}

int read_int(){
    int i,result;
    char buffer[11];
    for(i = 0;i < 10;i++){
        read(0,buffer+i,1);
        if(*(buffer+i) == '\n'){
            break;
        }
    }
    *(buffer+i) = 0;
    if((result = transfer(buffer)) == -1){
        write(1,"Invalid input.\n",15);
        return -1;
    }
    return result;
}

void create_chunk()
{
    if(chunk_number > 0x2f){
        write(1,"no more chunk.\n",15);
        return;
    }
    chunk_number++;
    chunk* tmp = (chunk*)malloc(0x14);
    write(1,"content: ",9);
    tmp->len = read(0,tmp->buffer,0x10);
    list[chunk_number] = tmp;
    write(1,"create successfully.\n",21);
}

void read_chunk()
{
    int id;
    write(1,"id: ",4);
    if((id = read_int()) == -1){
        return;
    }
    if(id > chunk_number){
        write(1,"Index out of range.\n",20);
        return;
    }
    write(1,list[id]->buffer,list[id]->len);
}

void free_chunk(){
        int id,i;
        write(1,"id: ",4);
    if((id = read_int()) == -1){
        return;
    }
        if(id > chunk_number){
                write(1,"Index out of range.\n",20);
        return;
        }
    free(list[id]);
    chunk_number--;
    for(i = id;i < 0x2f;i++){
        list[i] = list[i+1];
    }
    write(1,"delete successfully\n",20);
}

int main(void){
    chunk_number = -1;
    char input[2];
    int selete;
    while(1){
        menu();
        read(0,input,2);
        input[1] = 0;
        if(!(selete = atoi(input))){
            write(1,"Invalid input.\n",15);
            continue;
        }
        switch(selete){
        case 1:
            create_chunk();
            break;
        case 2:
            read_chunk();
            break;
        case 3:
            free_chunk();
            break;
        case 4:
            write(1,"bye~\n",5);
            return 0;
        default:
            write(1,"Invalid input\n",15);
        }
    }
}