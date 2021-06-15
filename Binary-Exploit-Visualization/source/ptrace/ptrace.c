#include <sys/wait.h>
#include <unistd.h>     /* For fork() */
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>   /* For constants ORIG_RAX etc */
#include <sys/user.h>
#include <sys/syscall.h> /* SYS_write */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <sys/vfs.h>
#include <sys/select.h>

#define DEBUG 0
#if DEBUG == 0
#define B64_ENCODE 1
#endif

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

// returns a buffer, containing the str wanted
#define alloc_printf(_str...) ({ \
    char* _tmp; \
    size_t _len = snprintf(NULL, 0, _str); \
    if (_len < 0) {perror("Whoa, snprintf() fails?!"); abort();}\
    _tmp = malloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })

//print debug info
#define debug_info(_str...) \
do {\
    if(DEBUG){\
        fprintf(stderr, "%s, %d: ", __FILE__, __LINE__); \
        fprintf(stderr, _str); \
    }\
}while(0)

#define ull unsigned long long

ull load_ull(int pid, ull addr){
    ull result = 0;
    for(int i = 0; i < 8; i++){
        *((char*)&result + i) = ptrace(PTRACE_PEEKDATA, pid, addr+i, NULL);
    }
    return result;
}

// base64 encoding goes here, skip please
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}


unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
                          + (sextet_b << 2 * 6)
                          + (sextet_c << 1 * 6)
                          + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}


void base64_cleanup() {
    free(decoding_table);
}


/* global variables for each implemented syscall */
int out_fd;

int open_calling = 0;

int read_calling = 0;
ull read_fd;
ull read_addr;
ull read_size;
ull read_realsize;

int write_calling = 0;
ull write_fd;
ull write_addr;
ull write_size;
ull write_realsize;


int mprotect_calling = 0;
int arch_prctl_calling = 0;
int munmap_calling = 0;

/********************************************************************/
/**********************syscall record list***************************/

/*store information by list*/
typedef struct CONTENT_LIST{
    size_t size;
    char* content;
    struct CONTENT_LIST* next;
}content_list;

/*store syscall's information from one thread/process*/
typedef struct SYSCALL_LIST{
    pid_t pid;
    content_list* head;
    content_list* tail;
    struct SYSCALL_LIST* pre;
    struct SYSCALL_LIST* next;
}syscall_list;

/*mapping according to syscalls's number*/
syscall_list* call_table[512];

/*initialize call_table*/
void call_table_init() {
    for(int i=0;i<512;i++) {
        call_table[i] = NULL;
    }
}

content_list* create_content_node() {
    content_list* node = (content_list*)malloc(sizeof(content_list));
    node->size = 0;
    node->content = NULL;
    node->next = NULL;
    return node;
}

syscall_list* create_syscall_node() {
    syscall_list* node = (syscall_list*)malloc(sizeof(syscall_list));
    node->pid = 0;
    node->head = create_content_node();
    node->tail = node->head;
    node->pre = NULL;
    node->next = NULL;
    return node;
}

/* add new str into content list*/
content_list* add_content_list(content_list* p, char* str, size_t size) {
    p->next = create_content_node();
    p = p->next;
    p->content = (char*)malloc(size);
    p->size = size;
    memcpy(p->content, str, size);
    return p;
}

/* add new content into the syscalls' table*/
void add_syscall_table(long sysno, pid_t pid, char *str, size_t size) {
//    printf("pid: %d sysno: %d size: %d\n", pid, sysno, size);
    if(call_table[sysno] == NULL) {
        call_table[sysno] = create_syscall_node();
        call_table[sysno]->pid = pid;
        call_table[sysno]->tail = add_content_list(call_table[sysno]->tail, str, size);
    }
    else{
        syscall_list* p = call_table[sysno];
        while(p != NULL) {
            if(p->pid == pid) {
                p->tail = add_content_list(p->tail, str, size);
                return;
            }
            if(p->next == NULL)
                break;
            p = p->next;
        }
        p->next = create_syscall_node();
        p->next->pre = p;
        p = p->next;
        p->pid = pid;
        p->tail = add_content_list(p->tail, str, size);
    }
}

/* clean list */
void remove_content_list(content_list* p) {
    content_list* tail = p->next;
    while(p != NULL) {
//        printf("size: %d\n", p->size);
        free(p);
        p = tail;
        if(p == NULL)
            break;
        tail = p->next;
    }
}

/* clean list */
void remove_syscall_table(long sysno, pid_t pid) {
//    printf("delete pid: %d sysno: %d\n", pid, sysno);
    if(call_table[sysno] == NULL)
        return;
    if(call_table[sysno]->pid == pid) {
        syscall_list* p = call_table[sysno]->next;
        remove_content_list(call_table[sysno]->head);
        free(call_table[sysno]);
        call_table[sysno] = p;
        if(p != NULL) {
            p->pre = NULL;
        }
        return;
    }
    syscall_list* p = call_table[sysno];
    while(p != NULL) {
        if(p->pid == pid) {
            remove_content_list(p->head);
            syscall_list* pre = p->pre;
            syscall_list* next = p->next;
            free(p);
            pre->next = next;
            if(next != NULL) {
                next->pre = pre;
            }
            return;
        }
        p = p->next;
    }
}

/* write strs in content list into file */
void output_from_talbe_node(long sysno, pid_t pid, int fd) {
    if(call_table[sysno] == NULL)
        return;
    syscall_list* p = call_table[sysno];
    while(p != NULL) {
        if(p->pid == pid) {
            content_list* content_p = p->head;
            while(content_p != NULL) {
                if(content_p->size == 0) {
                    content_p = content_p->next;
                    continue;
                }
                write(fd ,content_p->content, content_p->size);
//                write(1, content_p->content, content_p->size);
                content_p = content_p->next;
            }
            break;
        }
    }
}
/**********************syscall record list***************************/
/********************************************************************/

int close_calling = 0;

int stat_calling = 0;
ull stat_path;
ull stat_buf_ptr;
ull stat_stat_size = 0x90; //sizeof(struct stat);

int fstat_calling = 0;
ull fstat_fd;
ull fstat_buf_ptr;
ull fstat_stat_size = 0x90; //sizeof(struct stat);

int lstat_calling = 0;
ull lstat_path;
ull lstat_buf_ptr;
ull lstat_stat_size = 0x90; //sizeof(struct stat);

int socket_calling = 0;

int connect_calling = 0;

int mmap_calling = 0;
ull mmap_length;

int accept_calling = 0;

int recvmsg_calling = 0;
ull msghdr_ptr;

int recvfrom_calling = 0;
ull recvfrom_ubuf;

int sendto_calling = 0;
ull sendto_buf;

int sendmsg_calling = 0;
ull sendmsg_msghdr;

int getrandom_calling = 0;
ull getrandom_buf;
ull getrandom_size;

int clone_calling = 0;

int fork_calling = 0;

int vfork_calling = 0;
int time_calling = 0;
int times_calling = 0;

int writev_calling = 0;

int brk_calling = 0;

int poll_calling = 0;
ull poll_fds;

int lseek_calling = 0;

int ioctl_calling = 0;
ull ioctl_cmd;
ull ioctl_buf;
ull ioctl_realsize;

int select_calling = 0;
ull select_nfds;
ull select_readfds_ptr;
ull select_writefds_ptr;
ull select_exceptfds_ptr;
ull select_timeout_ptr;
ull select_fd_set_size = sizeof(fd_set);
ull select_timeval_size = sizeof(struct timeval);

int alarm_calling = 0;
ull alarm_seconds;

int getsockopt_calling = 0;
ull getsockopt_optval;
ull getsockopt_optlen_ptr;

int getpgrp_calling = 0;

int fcntl_calling = 0;

//int rt_sigaction_calling = 0;
//ull rt_sigaction_act;
//ull rt_sigaction_oldact;

int clock_getres_calling = 0;
ull clock_getres_clockid;
ull clock_getres_res_ptr;
ull clock_getres_timespec_size = 0x10; //sizeof(struct timespec)

int clock_gettime_calling = 0;
ull clock_gettime_clockid;
ull clock_gettime_res_ptr;
ull clock_gettime_timespec_size = 0x10; //sizeof(struct timespec)

int statfs_calling = 0;
ull statfs_path;
ull statfs_buf_ptr;
ull statfs_statfs_size = 0x78; //sizeof(struct statfs);

ull get_ioctl_change_size(ull cmd) {
    ull size = 0;
    switch(cmd){
        case SIOCGIFADDR:
        case SIOCSIFADDR:
            size = 0x28; //sizeof(struct ifreq)
            break;
        case TCGETS:
        case TCSETS:
        case TCSETAW:
        case TCSETAF:
            size = 0x3c; //sizeof(struct termios)
        case TIOCGPGRP:
        case TIOCSPGRP:
        case TIOCGSID:
            size = sizeof(pid_t);
        default:
            break;
    }
    return size;
}

ull elf_entry = 0;
ull elf_loadaddr = 0;

ull elf_pokebak = 0;


static inline void dump_segment(char* line, int fd, size_t size, pid_t pid){
    unsigned long long start, end;
    char prot[0x20] = {0};
    sscanf(line, "%llx-%llx %s", &start, &end, prot);
    if (elf_loadaddr == 0){ elf_loadaddr = start;  debug_info("loadaddr: %llx\n", start);}
    debug_info("start: %llx-%llx\n", start, end);
    debug_info("size: %llx\n", end-start);
    if (prot[1] == 'w' || prot[0] == 'r'){
        // describe this segment
        write(fd, line, size);
        write(fd, "\n", 1);

        char* buffer = malloc(end - start);
        if (!buffer){
            puts("OOM!");
            exit(0);
        }
        for(unsigned long long i = 0; i < end-start; i+=1){
            buffer[i] = ptrace(PTRACE_PEEKTEXT, pid, start + i, NULL);
        }
        size_t encoded_size;
        char* encoded_buffer = base64_encode(buffer, end-start, &encoded_size);
//        write(fd, "#######\n#######\n#######\n#######\n", 32);
//        puts("#######\n#######\n#######\n#######\n");
//        puts(encoded_buffer);
        write(fd, encoded_buffer, encoded_size);
        write(fd, "\n", 1);
        free(buffer);
        free(encoded_buffer);
    }

}

int do_memory_dump(char* map_file, pid_t pid){
    int map_fd = open(map_file, O_RDONLY);
    char* dump_file = alloc_printf("%s.dump", map_file);
    int dump_fd = open(dump_file, O_CREAT | O_RDWR, 0666);
    /* 清空文件 */
    ftruncate(dump_fd,0);
    /* 重新设置文件偏移量 */
    lseek(dump_fd,0,SEEK_SET);
    free(dump_file);
    char line_buffer[0x1000] = {0};
    size_t offset = 0;
    char buf;
    struct stat st;

    // dirty way to add one line(sp value) at the beginning of map
    if (stat(map_file, &st) == 0){
        size_t fsize = st.st_size;
        ull rsp = ptrace(PTRACE_PEEKUSER, pid, 8*RSP, NULL);
        char *sp_str = alloc_printf("got bp: %#llx\n", rsp);
        debug_info("%s", sp_str);
        char* tmp_map = malloc(fsize);
        assert(read(map_fd, tmp_map, fsize) == fsize);
        close(map_fd);
        int new_fd = open(map_file, O_RDWR | O_TRUNC | O_CREAT, 0666);
        assert(new_fd>=0);
        assert(write(new_fd, sp_str, strlen(sp_str)) == strlen(sp_str));
        assert(write(new_fd, tmp_map, fsize) == fsize);
        close(new_fd);
        free(tmp_map);
        free(sp_str);
        map_fd = open(map_file, O_RDONLY);
    }else{ perror("dump sp's stat: "); exit(0); }

    int first_line = 1;
    while (read(map_fd, &buf, 1)){
        if (buf == '\n'){
            if(first_line){ first_line = 0; offset = 0;continue;}
            dump_segment(line_buffer, dump_fd, offset, pid);
            offset = 0;
        }else{
            line_buffer[offset++] = buf;
        }
    }
    close(dump_fd);
    close(map_fd);
}

int map_parser(pid_t pid){
    pid_t c = fork();
    if (c == 0){
        char* file = alloc_printf("cp -f /proc/%d/maps ./maps.%d && chmod 0666 ./maps.%d", pid, pid, pid);
        system(file);
        exit(0);
    }else{
        char* map_file = alloc_printf("maps.%d", pid);
        waitpid(c, 0, 0);
        if (!access(map_file, F_OK)){
            do_memory_dump(map_file, pid);
            free(map_file);
        }else{
            free(map_file);
            puts("map file copy failed!");
            exit(0);
        }
    }
    return 0;
}

int save_call_context(int sysno, pid_t pid){
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    char* tmp = alloc_printf("{\"sysno\": %d, \"rdi\": %#llx, \"rsi\": %#llx, \"rdx\": %#llx, \"r10\": %#llx, \"r8\": %#llx, \"rbp\": %#llx, \"rip\": %#llx}\n",\
        sysno, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.rbp, regs.rip);
    add_syscall_table(sysno, pid, tmp, strlen(tmp));
//    write(out_fd, tmp, strlen(tmp));
    free(tmp);
    return 0;
}

ull save_call_result(int sysno, pid_t pid){
    unsigned long long rax = ptrace(PTRACE_PEEKUSER, pid, 8 * RAX, NULL);
    char *tmp = alloc_printf("{\"is_result\": True, \"sysno\": %d, \"rax\": %#llx, \"mem_changes\": [", sysno, rax);
    add_syscall_table(sysno, pid, tmp, strlen(tmp));
    free(tmp);
    return rax;
}

char* get_ptr_content(ull ptr, ull size, pid_t pid) {
    char* buf = malloc(size);
    for(ull i = 0; i < size; i++)
        buf[i] = ptrace(PTRACE_PEEKDATA, pid, ptr+i, NULL);
    return buf;
}

void save_memory_change(ull addr, ull size, pid_t pid, int sysno){
    char* buf = malloc(size);
    for(ull i = 0; i < size; i++){
        buf[i] = ptrace(PTRACE_PEEKDATA, pid, addr+i, NULL);
    }
#ifdef B64_ENCODE
    size_t encoded_size;
    char* encoded_buf = base64_encode(buf, size, &encoded_size);
#endif

    char* tmp = alloc_printf("{\"addr\": %#llx, \"size\": %lld, \"content\": \"", addr, size);
//    write(out_fd, tmp, strlen(tmp));
    add_syscall_table(sysno, pid, tmp, strlen(tmp));
#ifdef B64_ENCODE
//        write(out_fd, encoded_buf, encoded_size);
    add_syscall_table(sysno, pid, encoded_buf, encoded_size);
#else
    //        write(out_fd, buf, size);
        add_syscall_table(sysno, pid, buf, size);
#endif
//    write(out_fd, "\"}, ", 4);
    add_syscall_table(sysno, pid, "\"}, ", 4);
}

void save_end(int sysno, pid_t pid){
//    write(out_fd, "]}\n", 3);
    add_syscall_table(sysno, pid, "]}\n", 3);
    output_from_talbe_node(sysno, pid, out_fd);
    remove_syscall_table(sysno, pid);
}

int main(int argc, char *argv[], char** envp) {
    long orig_rax;
    int status;
    int iscalling = 0;
    int is_init = 1;
    int mprotect_cnt = 4;
    struct user_regs_struct regs;
    ull elf_hdr[4];
    struct user_regs_struct regs_bak;

    //init the call_table
    call_table_init();

    // get entry point, we need break at there
    int elf_fd = open(argv[1], O_RDONLY);
    assert(read(elf_fd, elf_hdr, 0x20) == 0x20);
    close(elf_fd);
    elf_entry = elf_hdr[3];
    debug_info("elf entry:%llx\n", elf_entry);


    pid_t child_pid = fork();
    if(child_pid == 0)
    {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
//        execl("/bin/ping", "ping", "baidu.com", NULL);
        execvpe(argv[1], argv+1, envp);
    }
    else
    {
        out_fd = open("syscalls.record", O_RDWR | O_CREAT | O_TRUNC, 0666);
        int fd = -1;
        ull tmp_rip;

        while(1)
        {
//            pid_t child_waited = wait(&status);
            pid_t child_waited = waitpid(-1, &status, __WALL);//等待接收信号

            if (child_waited == -1)
                break;
            if (WIFEXITED(status)) {
                //线程结束时，收到的信号
                WEXITSTATUS(status);
//                break;
            }
            if(WIFSTOPPED(status)){
                int sig = WSTOPSIG(status);
                if (sig == SIGABRT || sig == SIGSEGV || sig == SIGILL || sig == SIGKILL)
                    break;
            }

            long orig_rax = ptrace(PTRACE_PEEKUSER, child_waited, 8 * ORIG_RAX, NULL);
            if(orig_rax != -1)
                debug_info("now syscall: %ld\n", orig_rax);

            if (is_init == 2 && child_waited == child_pid){
                tmp_rip = ptrace(PTRACE_PEEKUSER, child_waited, 8*RIP, NULL);
                // fucking rip points to next insn
                if (tmp_rip == elf_entry+1){
                    is_init = 0;
                    debug_info("is_init: 0\n");

                    ptrace(PTRACE_GETREGS, child_waited, NULL, &regs_bak);
                    regs_bak.rip -= 1;
                    ptrace(PTRACE_POKETEXT, child_waited, elf_entry, elf_pokebak);
                    ptrace(PTRACE_SETREGS, child_waited, NULL, &regs_bak);
                    map_parser(child_waited);
//                    ptrace(PTRACE_SYSCALL, child_waited, NULL, NULL);
//                    continue;
                }
                ptrace(PTRACE_SYSCALL, child_waited, NULL, NULL);
                continue;

            }

            switch(orig_rax){
                case SYS_execve:
                {
                    //trace multi-thread
                    //设置ptrace属性
                    long ptraceOption = PTRACE_O_TRACECLONE;
                    ptrace(PTRACE_SETOPTIONS, child_waited, NULL, ptraceOption);
                    if (unlikely(is_init == 1) && child_waited == child_pid){
                        map_parser(child_waited);
                        is_init = 2;
                        // trying to kill vdso， first find end of argv
//                        ull rsp = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSP, NULL);
//                        debug_info("got envp value: %#llx\n", rsp);
//                        ull argc = load_ull(child_waited, rsp);
//                        debug_info("got argc: %lld\n", argc);
//                        rsp += 8 * argc + 16;
                        // now rsp points to envp, find end of it
//                        while(1){
//                            ull envp_entry = load_ull(child_waited, rsp);
//                            //debug_info("rsp: %#llx envp: %#llx\n", rsp, envp_entry);
//
//                            rsp += 8;
//                            if (envp_entry == (ull)NULL) break;
//                        }
                        // now kill auxv type == 33, rsp now points to first auxv entry
//                        for(int i = 0; i < 20 ; i++){
//                            ull auxv_type = load_ull(child_waited, rsp + 16*i);
//                            ull auxv_val = load_ull(child_waited, rsp+16*i+8);
//                            //debug_info("found auxv type: %#lld AT_SYSINFO_EHDR: %#llx\n", auxv_type,auxv_val & 0xfff);
//                            if (auxv_type == 33 && (auxv_val & 0xfff) == 0){
//                                debug_info("we found the auxv AT_SYSINFO_EHDR: %#llx\n", auxv_val);
//                                ptrace(PTRACE_POKEDATA, child_waited, rsp, 1);
//                                break;
//                            }
//                        }

                        if (elf_loadaddr){
                            if (elf_entry < elf_loadaddr && elf_loadaddr>>12 != elf_entry>>12){
                                elf_entry = elf_entry + elf_loadaddr;
                            }
                            elf_pokebak = ptrace(PTRACE_PEEKTEXT, child_waited, elf_entry, NULL);
                            ull trap_code = elf_pokebak;
                            unsigned char *p = (unsigned char*) &trap_code;
                            // Trap 中断指令的十六进制数值
                            p[0] = 0xcc;
                            ptrace(PTRACE_POKETEXT, child_waited, elf_entry, trap_code);
                            ptrace(PTRACE_CONT, child_waited, NULL, NULL);
                            continue;
                        }
                    }
                }
                    break;

                /*system call number is 0*/
                case SYS_read:
                    if (!read_calling){
                        // 进入调用，获取参数
                        read_calling = 1;
                        read_fd = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDI, NULL);
                        read_addr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
                        read_size = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDX, NULL);
                        // 记录调用信息
                        save_call_context(SYS_read, child_waited);
                    }else{
                        // 从syscall返回
                        read_calling = 0;
                        // 记录返回信息
                        read_realsize = save_call_result(SYS_read, child_waited);
                        // 记录内存变化
                        save_memory_change(read_addr, read_realsize, child_waited, SYS_read);
                        // 加上结尾（手动构建的dict字符串）
                        save_end(SYS_read, child_waited);
                    }
                    break;

                /*system call number is 1*/
                case SYS_write:
                    if (!write_calling){
                        write_calling = 1;
                        write_fd = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDI, NULL);
                        write_addr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
                        write_size = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDX, NULL);
                        save_call_context(SYS_write, child_waited);
                    }else{
                        write_calling = 0;
                        write_realsize = save_call_result(SYS_write, child_waited);
                        save_memory_change(write_addr, write_realsize, child_waited, SYS_write);
                        save_end(SYS_write, child_waited);
                    }
                    break;

                /*system call number is 2*/
                case SYS_open:
                    if(!open_calling){
                        open_calling = 1;
                        save_call_context(SYS_open, child_waited);
                    }else{
                        open_calling = 0;
                        save_call_result(SYS_open, child_waited);
                        save_end(SYS_open, child_waited);
                    }
                    break;

//                case SYS_rt_sigaction:
//                    if(!rt_sigaction_calling) {
//                        rt_sigaction_calling = 1;
//                        rt_sigaction_act = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
//                        rt_sigaction_oldact = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDX, NULL);
//                        save_call_context(SYS_rt_sigaction, child_waited);
//                    }else{
//                        rt_sigaction_calling = 0;
//                        save_call_result(SYS_rt_sigaction, child_waited);
//                        save_memory_change(rt_sigaction_act, 0x98, child_waited, SYS_rt_sigaction);
//                        save_memory_change(rt_sigaction_oldact, 0x98, child_waited, SYS_rt_sigaction);
//                        save_end(SYS_rt_sigaction, child_waited);
//                    }
//                    break;

                /*system call number is 3*/
                case SYS_close:
                    if(!close_calling) {
                        close_calling = 1;
                        save_call_context(SYS_close, child_waited);
                    }else{
                        close_calling = 0;
                        save_call_result(SYS_close, child_waited);
                        save_end(SYS_close, child_waited);
                    }
                    break;

                /*system call number is 4*/
                case SYS_stat:
                    if(!stat_calling) {
                        stat_calling = 1;
                        // printf("stat size:%llx", stat_stat_size);
                        stat_path = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDI, NULL);
                        stat_buf_ptr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
                        save_call_context(SYS_stat, child_waited);
                    }else{
                        stat_calling = 0;
                        save_call_result(SYS_stat, child_waited);
                        save_memory_change(stat_buf_ptr, stat_stat_size, child_waited, SYS_stat);
                        save_end(SYS_stat, child_waited);
                    }
                    break;

                 /*system call number is 5*/
                case SYS_fstat:
                    if(!fstat_calling) {
                        fstat_calling = 1;
                        fstat_fd = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDI, NULL);
                        fstat_buf_ptr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
                        save_call_context(SYS_fstat, child_waited);
                    }else{
                        fstat_calling = 0;
                        save_call_result(SYS_fstat, child_waited);
                        save_memory_change(fstat_buf_ptr, fstat_stat_size, child_waited, SYS_fstat);
                        save_end(SYS_fstat, child_waited);
                    }
                    break;

                 /*system call number is 6*/
                case SYS_lstat:
                    if(!lstat_calling) {
                        lstat_calling = 1;
                        lstat_path = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDI, NULL);
                        lstat_buf_ptr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
                        save_call_context(SYS_lstat, child_waited);
                    }else{
                        lstat_calling = 0;
                        save_call_result(SYS_lstat, child_waited);
                        save_memory_change(lstat_buf_ptr, lstat_stat_size, child_waited, SYS_lstat);
                        save_end(SYS_lstat, child_waited);
                    }
                    break;

                /*system call number is 8*/
                case SYS_lseek:
                    if(!lseek_calling) {
                        lseek_calling = 1;
                        save_call_context(SYS_lseek, child_waited);
                    }else{
                        lseek_calling = 0;
                        save_call_result(SYS_lseek, child_waited);
                        save_end(SYS_lseek, child_waited);
                    }
                    break;

                case SYS_ioctl:
                    if(!ioctl_calling) {
                        ioctl_calling = 1;
                        ioctl_cmd = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
                        ioctl_buf = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDX, NULL);
                        save_call_context(SYS_ioctl, child_waited);
                    }else{
                        ioctl_calling = 0;
                        save_call_result(SYS_ioctl, child_waited);
                        ioctl_realsize = get_ioctl_change_size(ioctl_cmd);
                        save_memory_change(ioctl_buf, ioctl_realsize, child_waited, SYS_ioctl);
                        save_end(SYS_ioctl, child_waited);
                    }
                    break;

                /*system call number is 23*/
                case SYS_select:
                    if(select_calling) {
                        select_calling = 1;
                        save_call_context(SYS_select, child_waited);
                        select_readfds_ptr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
                        select_writefds_ptr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDX, NULL);
                        select_exceptfds_ptr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * R10, NULL);
                        select_timeout_ptr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * R8, NULL);
                    }else{
                        select_calling = 0;
                        save_call_result(SYS_select, child_waited);
                        save_memory_change(select_readfds_ptr, select_fd_set_size, child_waited, SYS_select);
                        save_memory_change(select_writefds_ptr, select_fd_set_size, child_waited, SYS_select);
                        save_memory_change(select_exceptfds_ptr, select_fd_set_size, child_waited, SYS_select);
                        save_memory_change(select_timeout_ptr, select_timeval_size, child_waited, SYS_select);
                        save_end(SYS_select, child_waited);
                    }
                    break;

                /*system call number is 37*/
                case SYS_alarm:
                    if(!alarm_calling) {
                        alarm_calling = 1;
                        save_call_context(SYS_alarm, child_waited);
                    }else{
                        alarm_calling = 0;
                        save_call_result(SYS_alarm, child_waited);
                        save_end(SYS_alarm, child_waited);
                    }
                    break;
                /*system call number is 41*/
                case SYS_socket:
                    if(!socket_calling){
                        socket_calling = 1;
                        save_call_context(SYS_socket, child_waited);
                    }else{
                        socket_calling = 0;
                        save_call_result(SYS_socket, child_waited);
                        save_end(SYS_socket, child_waited);
                    }
                    break;
                /*system call number is 42*/
                case SYS_connect:
                    if(!connect_calling){
                        connect_calling = 1;
                        save_call_context(SYS_connect, child_waited);
                    }else{
                        connect_calling = 0;
                        save_call_result(SYS_connect, child_waited);
                        save_end(SYS_connect, child_waited);
                    }
                    break;
                /*system call number is 43*/
                case SYS_accept:
                    if(!accept_calling){
                        accept_calling = 1;
                        save_call_context(SYS_accept, child_waited);
                    }else{
                        accept_calling = 0;
                        save_call_result(SYS_accept, child_waited);
                        save_end(SYS_accept, child_waited);
                    }
                    break;
                /*system call number is 55*/
                case SYS_getsockopt:
                    if(!getsockopt_calling) {
                        getsockopt_calling = 1;
                        getsockopt_optval = ptrace(PTRACE_PEEKUSER, child_waited, 8 * R10, NULL);
                        getsockopt_optlen_ptr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * R8, NULL);
                        save_call_context(SYS_getsockopt, child_waited);
                    }else{
                        getsockopt_calling = 0;
                        save_call_result(SYS_getsockopt, child_waited);
                        int* size_ptr = (int *)get_ptr_content(getsockopt_optlen_ptr, sizeof(int), child_waited);
                        //printf("####test%d %#llx\n", *size_ptr, size_ptr);
                        save_memory_change(getsockopt_optval, (ull)(*size_ptr), child_waited, SYS_getsockopt);
                        save_end(SYS_getsockopt, child_waited);
                        free(size_ptr);
                    }
                    break;
                /*system call number is 72*/
                case SYS_fcntl:
                    if(!fcntl_calling) {
                        fcntl_calling = 1;
                        save_call_context(SYS_fcntl, child_waited);
                    }else{
                        fcntl_calling = 0;
                        save_call_result(SYS_fcntl, child_waited);
                        save_end(SYS_fcntl, child_waited);
                    }
                    break;
                /*system call number is 47*/
                case SYS_recvmsg:
                    if(!recvmsg_calling){
                        recvmsg_calling = 1;
                        msghdr_ptr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
                        save_call_context(SYS_recvmsg, child_waited);
                    }else{
                        recvmsg_calling = 0;
                        struct msghdr* msghdr_buf = malloc(sizeof(struct msghdr));
                        for(int i = 0; i < sizeof(struct msghdr); i++){
                            *((char*)msghdr_buf+i) = ptrace(PTRACE_PEEKDATA, child_waited, msghdr_ptr+i, NULL);
                        }
                        struct iovec* iov_buf = malloc(sizeof(struct iovec));
                        for(int i=0;i<sizeof(struct iovec);i++) {
                            *((char*)iov_buf+i) = ptrace(PTRACE_PEEKDATA, child_waited, (ull)msghdr_buf->msg_iov+i, NULL);
                        }
                        ull msg_len = save_call_result(SYS_recvmsg, child_waited);
                        save_memory_change((ull)iov_buf->iov_base, msg_len, child_waited, SYS_recvmsg);
                        save_memory_change((ull)msghdr_ptr, sizeof(struct msghdr), child_waited, SYS_recvmsg);
                        save_memory_change((ull)msghdr_buf->msg_iov, sizeof(struct iovec), child_waited, SYS_recvmsg);
                        save_end(SYS_recvmsg, child_waited);
                        free(msghdr_buf);
                        free(iov_buf);
                    }
                    break;
                /*system call number is 45*/
                case  SYS_recvfrom:
                    if(!recvfrom_calling){
                        recvfrom_calling = 1;
                        recvfrom_ubuf = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
                        save_call_context(SYS_recvfrom, child_waited);
                    }else{
                        recvfrom_calling = 0;
                        ull msg_len = save_call_result(SYS_recvfrom, child_waited);
                        save_memory_change(recvfrom_ubuf, msg_len, child_waited, SYS_recvfrom);
                        save_end(SYS_recvfrom, child_waited);
                    }
                    break;

                case SYS_sendto:
                    if(!sendto_calling){
                        sendto_calling = 1;
                        sendto_buf = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
                        save_call_context(SYS_sendto, child_waited);
                    }else{
                        sendto_calling = 0;
                        ull msg_len = save_call_result(SYS_sendto, child_waited);
                        save_memory_change(sendto_buf, msg_len, child_waited, SYS_sendto);
                        save_end(SYS_sendto, child_waited);
                    }
                    break;
                case SYS_sendmsg:
                    if(!sendmsg_calling){
                        sendmsg_calling = 1;
                        sendmsg_msghdr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
                        save_call_context(SYS_sendmsg, child_waited);
                    }else{
                        sendmsg_calling = 0;
                        struct msghdr* msghdr_buf = malloc(sizeof(struct msghdr));
                        for(int i = 0; i < sizeof(struct msghdr); i++){
                            *((char*)msghdr_buf+i) = ptrace(PTRACE_PEEKDATA, child_waited, sendmsg_msghdr+i, NULL);
                        }
                        struct iovec* iov_buf = malloc(sizeof(struct iovec));
                        for(int i=0;i<sizeof(struct iovec);i++) {
                            *((char*)iov_buf+i) = ptrace(PTRACE_PEEKDATA, child_waited, (ull)msghdr_buf->msg_iov+i, NULL);
                        }
                        ull msg_len = save_call_result(SYS_recvmsg, child_waited);
                        save_memory_change((ull)iov_buf->iov_base, msg_len, child_waited, SYS_sendmsg);
                        save_end(SYS_sendmsg, child_waited);
                        free(msghdr_buf);
                        free(iov_buf);
                    }
                    break;
                case SYS_getrandom:
                    if(!getrandom_calling){
                        getrandom_calling = 1;
                        getrandom_buf = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDI, NULL);
                        save_call_context(SYS_getrandom, child_waited);
                    }else{
                        getrandom_calling = 0;
                        ull real_getrandom_size = save_call_result(SYS_getrandom, child_waited);
                        save_memory_change(getrandom_buf, real_getrandom_size, child_waited, SYS_getrandom);
                        save_end(SYS_getrandom, child_waited);
                    }
                    break;
                case SYS_time:
                    debug_info("%s", "calling time!\n");
                    if(!time_calling){
                        time_calling = 1;
                        save_call_context(SYS_time, child_waited);
                    }else{
                        time_calling = 0;
                        save_call_result(SYS_time, child_waited);
                        save_end(SYS_time, child_waited);
                    }
                    break;
                case SYS_times:
                    if(!times_calling){
                        times_calling = 1;
                        save_call_context(SYS_times, child_waited);
                    }else{
                        times_calling = 0;
                        save_call_result(SYS_times, child_waited);
                        save_end(SYS_times, child_waited);
                        save_end(SYS_times, child_waited);
                    }
                    break;
                case SYS_writev:
                    if(!writev_calling){
                        writev_calling = 1;
                        save_call_context(SYS_writev, child_waited);
                    }else{
                        writev_calling = 0;
                        save_call_result(SYS_writev, child_waited);
                        save_end(SYS_writev, child_waited);
                    }
                    break;

                case SYS_mmap:
                    if(!mmap_calling){
                        mmap_calling = 1;
                        mmap_length = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
                        save_call_context(SYS_mmap, child_waited);
                    }else{
                        mmap_calling = 0;
                        ull mmap_addr = save_call_result(SYS_mmap, child_waited);
                        save_memory_change(mmap_addr, mmap_length, child_waited, SYS_mmap);
                        save_end(SYS_mmap, child_waited);
                    }
                    break;

                case SYS_brk:
                    if(!brk_calling) {
                        brk_calling = 1;
                        save_call_context(SYS_brk, child_waited);
                    }else{
                        brk_calling = 0;
                        save_call_result(SYS_brk, child_waited);
                        save_end(SYS_brk, child_waited);
                    }
                    break;

                case SYS_poll:
                    if(!poll_calling) {
                        poll_calling = 1;
                        poll_fds = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDI, NULL);
                        save_call_context(SYS_poll, child_waited);
                    }else{
                        poll_calling = 0;
                        save_call_result(SYS_poll, child_waited);
                        save_memory_change(poll_fds, sizeof(struct pollfd), child_waited, SYS_poll);
                        save_end(SYS_poll, child_waited);
                    }
                    break;

//                case SYS_clone:
//                    if(!clone_calling) {
//                        clone_calling = 1;
//                    }else{
//                        clone_calling = 0;
//                        pid_t new_pid = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RAX, NULL);
//                        ptrace(PTRACE_ATTACH, new_pid, NULL, NULL);
//                    }
//                    break;
//
//                case SYS_fork:
//                    if(!fork_calling) {
//                        fork_calling = 1;
//                    }else{
//                        fork_calling = 0;
//                        pid_t new_pid = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RAX, NULL);
//                        ptrace(PTRACE_ATTACH, new_pid, NULL, NULL);
//                    }
//                    break;
//
//                case SYS_vfork:
//                    if(!vfork_calling) {
//                        vfork_calling = 1;
//                    }else{
//                        vfork_calling = 0;
//                        pid_t new_pid = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RAX, NULL);
//                        ptrace(PTRACE_ATTACH, new_pid, NULL, NULL);
//                    }
//                    break;

                /*system call number is 111*/
                case SYS_getpgrp:
                    if(!getpgrp_calling) {
                        getpgrp_calling = 1;
                        save_call_context(SYS_getpgrp, child_waited);
                    }else{
                        getpgrp_calling = 0;
                        save_call_result(SYS_getpgrp, child_waited);
                        save_end(SYS_getpgrp, child_waited);
                    }
                    break;

                /*system call number is 137*/
                case SYS_statfs:
                    if(!statfs_calling) {
                        statfs_calling = 1;
                        // printf("statfs size:%llx", statfs_statfs_size);
                        statfs_path = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDI, NULL);
                        statfs_buf_ptr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
						save_call_context(SYS_statfs, child_waited);
                    }else{
                        statfs_calling = 0;
                        save_call_result(SYS_statfs, child_waited);
                        save_memory_change(statfs_buf_ptr, statfs_statfs_size, child_waited, SYS_statfs);
                        save_end(SYS_statfs, child_waited);
                    }
                    break;

				/*system call number is 228*/
				case SYS_clock_gettime:
					if(!clock_gettime_calling) {
						clock_gettime_calling = 1;
						clock_gettime_clockid = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDI, NULL);
                        clock_gettime_res_ptr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
						save_call_context(SYS_clock_gettime, child_waited);
					}else{
						clock_gettime_calling = 0;
						save_call_result(SYS_clock_gettime, child_waited);
                        //clock_getres_timespec_size = sizeof(struct timespec);
						//printf("timespec size: %llx", clock_getres_timespec_size);
                        save_memory_change(clock_gettime_res_ptr, clock_gettime_timespec_size, child_waited, SYS_clock_gettime);
                        save_end(SYS_clock_gettime, child_waited);
					}
					break;

				/*system call number is 229*/
				case SYS_clock_getres:
					if(!clock_getres_calling) {
						clock_getres_calling = 1;
						clock_getres_clockid = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RDI, NULL);
                        clock_getres_res_ptr = ptrace(PTRACE_PEEKUSER, child_waited, 8 * RSI, NULL);
						save_call_context(SYS_clock_getres, child_waited);
					}else{
						clock_getres_calling = 0;
						save_call_result(SYS_clock_getres, child_waited);
                        //clock_getres_timespec_size = sizeof(struct timespec);
						//printf("timespec size: %llx", clock_getres_timespec_size);
                        save_memory_change(clock_getres_res_ptr, clock_getres_timespec_size, child_waited, SYS_clock_getres);
                        save_end(SYS_clock_getres, child_waited);
					}
					break;

                default:
                    break;
            }
            ptrace(PTRACE_SYSCALL, child_waited, NULL, NULL);
        }
        close(out_fd);
    }
    return 0;
}
