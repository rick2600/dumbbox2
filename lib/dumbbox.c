#include "dumbbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <seccomp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/epoll.h>


static bool running;
static int n_children;


static void dumbbox_fatal_error(const char* msg) {
    fprintf(stderr, "dumbbox error: %s\n", msg);
    exit(EXIT_FAILURE);
}


dumbbox_ipc_ctx_t* dumbbox_ipc_ctx_create() {
    dumbbox_ipc_ctx_t* ipc_ctx = malloc(sizeof(dumbbox_ipc_ctx_t));
    if (ipc_ctx == NULL) {
        dumbbox_fatal_error("can't alloc dumbbox_ipc_ctx_t");
    }
    memset(ipc_ctx, 0, sizeof(ipc_ctx));
    if (seccomp_notify_alloc(&ipc_ctx->req, &ipc_ctx->resp) != 0) {
        dumbbox_fatal_error("can't alloc seccomp_notif_*");
    }
    return ipc_ctx;
}


void dumbbox_ipc_ctx_destroy(dumbbox_ipc_ctx_t* ipc_ctx) {
    seccomp_notify_free(ipc_ctx->req, ipc_ctx->resp);
    free(ipc_ctx);
}


dumbbox_t* dumbbox_create() {
    dumbbox_t* dumbbox = malloc(sizeof(dumbbox_t));
    if (dumbbox == NULL) {
        dumbbox_fatal_error("can't alloc dumbbox_t");
    }
    for (int i = 0; i < MAX_SYSCALLS; i++) {
        dumbbox->sys_handlers[i] = NULL;
    }
    n_children = 0;
    return dumbbox;
}


void dumbbox_destroy(dumbbox_t* dumbbox) {
    free(dumbbox);
}


bool dumbbox_install_handler(dumbbox_t* dumbbox, int sys_number, sys_handler_t handler) {
    // TODO: check array access
    if (sys_number < MAX_SYSCALLS) {
        dumbbox->sys_handlers[sys_number] = handler;
        return true;
    }
    return false;
}


bool dumbbox_install_defhandler(dumbbox_t* dumbbox, sys_handler_t handler) {
    dumbbox->def_handler = handler;
    return true;
}


static int dumbbox_enter_sandbox() {
    scmp_filter_ctx ctx = NULL;
    ctx = seccomp_init(SCMP_ACT_NOTIFY);
    //ctx = seccomp_init(SCMP_ACT_KILL);

    if (ctx == NULL) return -1;
    // ALLOW only syscall allowed in SECCOMP_MODE_STRICT + close
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0)         != 0) return -1;
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0)        != 0) return -1;
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0)         != 0) return -1;
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0)   != 0) return -1;
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0) != 0) return -1;
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) != 0) return -1;
    if (seccomp_load(ctx) != 0) return -1;

    int notify_fd = seccomp_notify_fd(ctx);
    if (notify_fd < 0) return -1;
    return notify_fd;
}


static void dumbbox_setup_target(int sock[]) {
    int notify_fd = dumbbox_enter_sandbox();
    if (write(sock[1], &notify_fd, sizeof(int)) < 0) {
        dumbbox_fatal_error("can't write notify_fd");
    }
    close(sock[0]);
    close(sock[1]);
}


static void dumbbox_add_target_to_event_poll(dumbbox_t* dumbbox, int sock[], int child_pid) {
    int notify_fd;
    if (read(sock[0], &notify_fd, sizeof(int)) < 0) {
        dumbbox_fatal_error("can't read notify_fd");
    }
    close(sock[0]);
    close(sock[1]);

    // Get a fd from child's descriptor table
    int target_pidfd =  syscall(SYS_pidfd_open, child_pid, 0);
    int local_notify_fd = syscall(SYS_pidfd_getfd, target_pidfd, notify_fd, 0);
    close(target_pidfd);

    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = local_notify_fd;
    epoll_ctl(dumbbox->epoll_fd, EPOLL_CTL_ADD, local_notify_fd, &event);
    n_children++;
}


void dumbbox_run(dumbbox_t* dumbbox, void (*target)(void)) {
    int sock[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock) < 0) {
        dumbbox_fatal_error("can't create socketpair");
    }
    pid_t pid = fork();
    if (pid == 0) {
        dumbbox_setup_target(sock);
        target();
    } else {
        dumbbox_add_target_to_event_poll(dumbbox, sock, pid);
    }

}

ssize_t dumbbox_read_remote_mem(dumbbox_ipc_ctx_t* ipc_ctx, __u64 addr, void* buf, size_t size) {
    // TODO: check return values
    char mem_path[64];
    sprintf(mem_path, "/proc/%d/mem", ipc_ctx->req->pid);
    int fd = open(mem_path, O_RDONLY);

    ssize_t nread = pread(fd, buf, size, addr);
    close(fd);
    return nread;
}


char* dumbbox_read_remote_string_at(dumbbox_ipc_ctx_t* ipc_ctx, __u64 addr) {
    size_t chunk_size = 128;
    size_t buf_capacity = chunk_size;
    size_t buf_size = 0;
    char* buf = (char*)malloc(buf_capacity * sizeof(char));
    if (buf == NULL) return NULL;

    char mem_path[64];
    sprintf(mem_path, "/proc/%d/mem", ipc_ctx->req->pid);
    int fd = open(mem_path, O_RDONLY);

    while (1) {
        ssize_t nread = pread(fd, buf + buf_size, chunk_size, addr + buf_size);
        if (nread < 0) {
            close(fd);
            free(buf);
            return NULL;
        }
        buf_size += nread;
        if (memchr(buf, 0, buf_size) != NULL) break;
        if (buf_size == buf_capacity) {
            buf_capacity += chunk_size;
            buf = (char*)realloc(buf, buf_capacity * sizeof(char));
            if (buf == NULL) {
                close(fd);
                return NULL;
            }
        }
    }
    return buf;
}


void dumbbox_allow_syscall(dumbbox_ipc_ctx_t* ipc_ctx) {
    ipc_ctx->resp->id = ipc_ctx->req->id;
    ipc_ctx->resp->val = 0;
    ipc_ctx->resp->error = 0;
    ipc_ctx->resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    seccomp_notify_respond(ipc_ctx->notify_fd, ipc_ctx->resp);
}


void dummbbox_kill_with_bad_syscall(dumbbox_ipc_ctx_t* ipc_ctx) {
    kill(ipc_ctx->req->pid, SIGSYS);
}


int dumbbox_send_fd(dumbbox_ipc_ctx_t* ipc_ctx, int fd) {
    ipc_ctx->addfd.id = ipc_ctx->req->id;
    ipc_ctx->addfd.srcfd = fd;
    ipc_ctx->addfd.newfd = 0;
    ipc_ctx->addfd.flags = 0;
    ipc_ctx->addfd.newfd_flags = O_CLOEXEC;
    int remote_fd = ioctl(ipc_ctx->notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &ipc_ctx->addfd);
    return remote_fd;
}


void dumbbox_respond_with_fd(dumbbox_ipc_ctx_t* ipc_ctx, int fd) {
    int remote_fd = dumbbox_send_fd(ipc_ctx, fd);
    ipc_ctx->resp->id = ipc_ctx->req->id;
    ipc_ctx->resp->val = remote_fd;
    ipc_ctx->resp->error = 0;
    ipc_ctx->resp->flags = 0;
    seccomp_notify_respond(ipc_ctx->notify_fd, ipc_ctx->resp);
}


void dumbbox_respond_with_error(dumbbox_ipc_ctx_t* ipc_ctx, int error) {
    ipc_ctx->resp->id = ipc_ctx->req->id;
    ipc_ctx->resp->val = 0;
    ipc_ctx->resp->error = -error;
    ipc_ctx->resp->flags = 0;
    seccomp_notify_respond(ipc_ctx->notify_fd, ipc_ctx->resp);
}


static void* dumbbox_syscall_monitor(void* arg) {
    struct epoll_event ep_events[MAX_EVENTS];
    void *ret = NULL;
    dumbbox_t* dumbbox = (dumbbox_t *)arg;
    dumbbox_ipc_ctx_t* ipc_ctx = dumbbox_ipc_ctx_create();

    int nfds;
    int rc;

    while (running) {
        nfds = epoll_wait(dumbbox->epoll_fd, ep_events, MAX_EVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            if  ((ep_events[i].events & EPOLLIN) == EPOLLIN) {
                memset(ipc_ctx->req, 0, sizeof(struct seccomp_notif));
                ipc_ctx->notify_fd = ep_events[i].data.fd;

                rc = seccomp_notify_receive(ipc_ctx->notify_fd, ipc_ctx->req);
                if (rc < 0) continue;
                rc = seccomp_notify_id_valid(ipc_ctx->notify_fd, ipc_ctx->req->id);
                if (rc != 0) continue;
                int sys_number = ipc_ctx->req->data.nr;
                if (sys_number >= MAX_SYSCALLS) continue;

                //char *sys_name = SYS_NUMBER2NAME(sys_number);
                int pid = ipc_ctx->req->pid;
                sys_handler_t handler = dumbbox->sys_handlers[sys_number];

                /*
                printf("PID %d requested syscall '%s' (%d) - handler: %p\n",
                       pid, sys_name, sys_number, handler);
                */
                if (handler != NULL)
                    handler(ipc_ctx);
                else
                    dumbbox->def_handler(ipc_ctx);
            }
        }
    }
    dumbbox_ipc_ctx_destroy(ipc_ctx);
    pthread_exit(ret);
}


void sigint_handler(int dummy) {
    running = false;
    exit(EXIT_SUCCESS);
}


void sigchld_handler(int dummy) {
    n_children--;
    /*
    if (n_children <= 0) {
        running = false;
        exit(EXIT_SUCCESS);
    }
    */
}


void dumbbox_start(dumbbox_t* dumbbox) {
    running = true;
    dumbbox->epoll_fd = epoll_create1(0);
    if (dumbbox->epoll_fd < 0) {
        dumbbox_fatal_error("epoll_create1() error");
    }

    if (pthread_create(&dumbbox->monitor_thid, NULL, dumbbox_syscall_monitor, dumbbox) != 0) {
        dumbbox_fatal_error("pthread_create() error");
    }
    signal(SIGINT, sigint_handler);
    signal(SIGCHLD, sigchld_handler);
}


void dumbbox_wait(dumbbox_t* dumbbox) {
    void *ret;
    if (pthread_join(dumbbox->monitor_thid, &ret) != 0) {
        dumbbox_fatal_error("pthread_join() error");
    }
}
