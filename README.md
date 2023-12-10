# Dumbbox2
A skeleton to create sandbox challenges for learning purposes.

THIS SHOULD NOT BE USED AS REAL SANDBOX LIB!

# example.c
In the example the sandoxed process is only allowed to read the file /etc/issue

### Compilation
```
sudo apt install libseccomp-dev
gcc -o example example.c lib/dumbbox.c -I./lib -lseccomp -lpthread
```

# How does it work?

1. The supervisor creates one or more processes;
2. Each child process setups a sandbox using seccomp notification mechanism;
3. Each child process informs the supervisor via socketpair the file descriptor number to be used to send/recv notifications;
4. The supervisor uses pidfd_getfd() to get a copy of the file descriptor from the child;
5. The supervisor adds this file descriptor to a poll of events (epoll);
6. The supervisor in a separated thread waits for events (syscalls requests) and forwards to code to handle it;
7. When the supervisor needs to send a file descriptor to child it uses ioctl + SECCOMP_IOCTL_NOTIF_ADDFD.

# Features used
* Seccomp notification mechanism
* pidfd_getfd
* SECCOMP_IOCTL_NOTIF_ADDFD
* epoll

# References
* https://brauner.io/2020/07/23/seccomp-notify.html
* https://github.com/seccomp/libseccomp/blob/main/tests/51-live-user_notification.c
* https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html
