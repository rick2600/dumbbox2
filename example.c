#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <signal.h>
#include "dumbbox.h"



void forward_open_result(dumbbox_ipc_ctx_t* ipc_ctx, int fd) {
    if (fd < 0)
        dumbbox_respond_with_error(ipc_ctx, errno);
    else {
        dumbbox_respond_with_fd(ipc_ctx, fd);
        close(fd);
    }
}


void sys_open_handler(dumbbox_ipc_ctx_t* ipc_ctx) {
    __u64 *args = ipc_ctx->req->data.args;
    char* path = dumbbox_read_remote_string_at(ipc_ctx, args[0]);
    bool allowed = strcmp(path, "/etc/issue") == 0;
    if (allowed) {
        int fd = open(path, args[1], args[2]);
        forward_open_result(ipc_ctx, fd);

    } else {
        dumbbox_respond_with_error(ipc_ctx, EACCES);
    }

    printf("[PID %d (S)] - open(\"%s\", %lld, %lld) - %s\n",
           getpid(), path, args[1], args[2], allowed ? "ALLOWED":"DENIED");
    free(path);
}


void sys_openat_handler(dumbbox_ipc_ctx_t* ipc_ctx) {
    __u64 *args = ipc_ctx->req->data.args;
    char* path = dumbbox_read_remote_string_at(ipc_ctx, args[1]);
    bool allowed = strcmp(path, "/etc/issue") == 0;
    if (allowed) {
        int fd = openat(args[0], path, args[2], args[3]);
        forward_open_result(ipc_ctx, fd);
    } else {
        dumbbox_respond_with_error(ipc_ctx, EACCES);
    }
    printf("[PID %d (S)] - openat(0x%llx, \"%s\", %lld, %lld) - %s\n",
           getpid(), args[0], path, args[2], args[3], allowed ? "ALLOWED":"DENIED");
    free(path);
}


void def_handler(dumbbox_ipc_ctx_t* ipc_ctx) {
    int sys_number = ipc_ctx->req->data.nr;
    switch (sys_number) {
        case SYS_getpid:
        case SYS_clock_nanosleep:
        case SYS_fstat:
            dumbbox_allow_syscall(ipc_ctx);
            break;

        default:
            printf("Syscall '%s' (%d) is unhandled\n",
                   SYS_NUMBER2NAME(sys_number), sys_number);
            dummbbox_kill_with_bad_syscall(ipc_ctx);
            break;
    }

}


/* This function will run "sandboxed" */
void traced_function(void) {
    char buf[4096] = {0};

    // /etc/issue is allowed
    char *files[] = {"/etc/issue", "/etc/passwd"};
    for (int i = 0; i < sizeof(files)/sizeof(files[0]); i++) {
        int fd = open(files[i], O_RDONLY);
        if (fd < 0) continue;
        ssize_t nread = read(fd, buf, sizeof(buf)-1);
        if (nread > 0) {
            buf[nread] = 0;
            char* newline = strchr(buf, '\n');
            if (newline != NULL) *newline = 0;
        }
        printf("[PID %d (T)] - Content: %s\n\n", getpid(), buf);
        //sleep(3);
        close(fd);
    }
    exit(EXIT_SUCCESS);
}


int main(int argc, char** argv) {
    dumbbox_t* dumbbox = dumbbox_create();
    dumbbox_install_defhandler(dumbbox, def_handler);
    dumbbox_install_handler(dumbbox, SYS_open, sys_open_handler);
    dumbbox_install_handler(dumbbox, SYS_openat, sys_openat_handler);

    dumbbox_start(dumbbox);
    dumbbox_run(dumbbox, traced_function);
    dumbbox_run(dumbbox, traced_function);
    dumbbox_wait(dumbbox);

    exit(EXIT_SUCCESS);
}