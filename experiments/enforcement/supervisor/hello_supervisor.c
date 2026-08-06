/*
 * Phase 1 supervisor — minimal seccomp-notify "hello world".
 *
 * What this does:
 *   1. Create a socketpair for passing the seccomp notif fd back.
 *   2. Fork.
 *   3. Child: install a seccomp filter with USER_NOTIF on openat,
 *      pass the returned notif fd back to the parent via SCM_RIGHTS,
 *      exec the target program.
 *   4. Parent: receive the notif fd from the child, loop on
 *      SECCOMP_IOCTL_NOTIF_RECV, print each openat's path, ALLOW via
 *      SECCOMP_USER_NOTIF_FLAG_CONTINUE.
 *
 * Success criterion: target runs to completion. Every openat is
 * printed by the supervisor with the exact path. Target sees no
 * errors — the CONTINUE flag makes the kernel run the syscall
 * normally after the notification.
 *
 * Build:  make hello_supervisor
 * Run:    ./hello_supervisor /bin/cat /etc/hostname
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int sys_seccomp(unsigned int op, unsigned int flags, void *args) {
    errno = 0;
    return (int)syscall(SYS_seccomp, op, flags, args);
}

/* Filter: on openat, USER_NOTIF; on everything else, ALLOW. */
static int install_seccomp_filter(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return -1;
    }
    int fd = sys_seccomp(SECCOMP_SET_MODE_FILTER,
                          SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (fd < 0) perror("seccomp(SET_MODE_FILTER)");
    return fd;
}

/* Send `fd` over the unix socket `sock`. */
static int send_fd(int sock, int fd) {
    char dummy = 'x';
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    char ctrl[CMSG_SPACE(sizeof(int))];
    memset(ctrl, 0, sizeof(ctrl));
    struct msghdr msg = {
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = ctrl, .msg_controllen = sizeof(ctrl),
    };
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    if (sendmsg(sock, &msg, 0) < 0) {
        perror("sendmsg");
        return -1;
    }
    return 0;
}

/* Receive an fd from the unix socket `sock`. Returns the fd on success. */
static int recv_fd(int sock) {
    char dummy;
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    char ctrl[CMSG_SPACE(sizeof(int))];
    memset(ctrl, 0, sizeof(ctrl));
    struct msghdr msg = {
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = ctrl, .msg_controllen = sizeof(ctrl),
    };
    if (recvmsg(sock, &msg, 0) < 0) {
        perror("recvmsg");
        return -1;
    }
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (!c || c->cmsg_type != SCM_RIGHTS) {
        fprintf(stderr, "recv_fd: no fd in cmsg\n");
        return -1;
    }
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof(int));
    return fd;
}

/* Read a NUL-terminated path from /proc/<pid>/mem at `addr`. */
static ssize_t read_target_path(pid_t pid, unsigned long long addr,
                                 char *buf, size_t buf_size) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/mem", pid);
    int fd = open(proc_path, O_RDONLY);
    if (fd < 0) {
        perror("open /proc/<pid>/mem");
        return -1;
    }
    ssize_t n = pread(fd, buf, buf_size - 1, (off_t)addr);
    close(fd);
    if (n < 0) {
        perror("pread /proc/<pid>/mem");
        return -1;
    }
    for (ssize_t i = 0; i < n; ++i) {
        if (buf[i] == '\0') return i;
    }
    buf[n] = '\0';
    return n;
}

/* CONTINUE reply: kernel executes the syscall normally. */
static int notif_continue(int notif_fd, __u64 id) {
    struct seccomp_notif_resp resp = {
        .id = id, .val = 0, .error = 0,
        .flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
        perror("SECCOMP_IOCTL_NOTIF_SEND");
        return -1;
    }
    return 0;
}

static int run_supervisor(int notif_fd) {
    struct seccomp_notif req;
    for (;;) {
        memset(&req, 0, sizeof(req));
        if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOENT) {
                fprintf(stderr, "[supervisor] target exited\n");
                return 0;
            }
            perror("SECCOMP_IOCTL_NOTIF_RECV");
            return -1;
        }
        char path[4096];
        ssize_t n = read_target_path((pid_t)req.pid, req.data.args[1],
                                      path, sizeof(path));
        if (n < 0) {
            fprintf(stderr, "[supervisor] pid=%d openat: <unreadable>\n",
                    req.pid);
        } else {
            fprintf(stderr, "[supervisor] pid=%d openat: %s\n",
                    req.pid, path);
        }
        if (notif_continue(notif_fd, req.id) < 0) return -1;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <target_binary> [args...]\n", argv[0]);
        return 2;
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("socketpair");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        /* Child */
        close(sv[0]);
        int notif_fd = install_seccomp_filter();
        if (notif_fd < 0) {
            close(sv[1]);
            _exit(1);
        }
        if (send_fd(sv[1], notif_fd) < 0) {
            close(sv[1]);
            _exit(1);
        }
        close(sv[1]);
        close(notif_fd);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        _exit(127);
    }

    /* Parent */
    close(sv[1]);
    int notif_fd = recv_fd(sv[0]);
    close(sv[0]);
    if (notif_fd < 0) {
        fprintf(stderr, "[supervisor] failed to receive notif fd\n");
        waitpid(pid, NULL, 0);
        return 1;
    }
    fprintf(stderr, "[supervisor] got notif fd=%d, entering loop\n", notif_fd);
    run_supervisor(notif_fd);

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        fprintf(stderr, "[supervisor] target exited status=%d\n",
                WEXITSTATUS(status));
    } else {
        fprintf(stderr, "[supervisor] target terminated abnormally\n");
    }
    close(notif_fd);
    return 0;
}
