#ifndef DUMBBOX_H
#define DUMBBOX_H

/*
References

https://github.com/seccomp/libseccomp/blob/main/tests/51-live-user_notification.c
https://manpages.courier-mta.org/htmlman2/seccomp_unotify.2.html
https://man7.org/tlpi/code/online/dist/seccomp/seccomp_unotify_openat.c
https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2021/05/20/seccomp-user-notify

*/

#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <sys/epoll.h>
#include <seccomp.h>


#define MAX_EVENTS                10
#define MAX_SYSCALLS            1024

#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif

#ifndef SECCOMP_IOCTL_NOTIF_ADDFD
#define SECCOMP_IOCTL_NOTIF_ADDFD   SECCOMP_IOW(3, struct seccomp_notif_addfd)

/* valid flags for seccomp_notif_addfd */
#define SECCOMP_ADDFD_FLAG_SETFD        (1UL << 0) /* Specify remote fd */

struct seccomp_notif_addfd {
    __u64 id;           /* Cookie from SECCOMP_IOCTL_NOTIF_RECV */
    __u32 flags;        /* Flags:
                           SECCOMP_ADDFD_FLAG_SETFD: allow target FD
                           to be selected via 'newfd' field. */
    __u32 srcfd;        /* FD to duplicate in supervisor */
    __u32 newfd;        /* 0, or desired FD number in target */
    __u32 newfd_flags;  /* Flags to set om target FD (O_CLOEXEC) */
};

#define SECCOMP_IOC_MAGIC               '!'
#define SECCOMP_IO(nr)                  _IO(SECCOMP_IOC_MAGIC, nr)
#define SECCOMP_IOR(nr, type)           _IOR(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOW(nr, type)           _IOW(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOWR(nr, type)          _IOWR(SECCOMP_IOC_MAGIC, nr, type)
#endif


#define SYS_NUMBER2NAME(n) seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (n))


typedef struct {
    int notify_fd;
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
    struct seccomp_notif_addfd addfd;
} dumbbox_ipc_ctx_t;

typedef void (*sys_handler_t)(dumbbox_ipc_ctx_t* ipc_ctx);

typedef struct {
    int epoll_fd;
    pthread_t monitor_thid;

    // FIX: size based on available syscalls
    sys_handler_t sys_handlers[MAX_SYSCALLS];
    sys_handler_t def_handler;

} dumbbox_t;

dumbbox_t* dumbbox_create();
void dumbbox_destroy(dumbbox_t* dumbbox);
bool dumbbox_install_handler(dumbbox_t* dumbbox, int sys_number, sys_handler_t handler);
bool dumbbox_install_defhandler(dumbbox_t* dumbbox, sys_handler_t handler);
void dumbbox_run(dumbbox_t* dumbbox, void (*target)(void));
ssize_t dumbbox_read_remote_mem(dumbbox_ipc_ctx_t* ipc_ctx, __u64 addr, void* buf, size_t size);
char* dumbbox_read_remote_string_at(dumbbox_ipc_ctx_t* ipc_ctx, __u64 addr);
void dumbbox_allow_syscall(dumbbox_ipc_ctx_t* ipc_ctx);
void dummbbox_kill_with_bad_syscall(dumbbox_ipc_ctx_t* ipc_ctx);
void dumbbox_respond_with_fd(dumbbox_ipc_ctx_t* ipc_ctx, int fd);
void dumbbox_respond_with_error(dumbbox_ipc_ctx_t* ipc_ctx, int error);
void dumbbox_start(dumbbox_t* dumbbox);
void dumbbox_wait(dumbbox_t* dumbbox);

#endif