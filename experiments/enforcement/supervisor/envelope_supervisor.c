/*
 * Envelope supervisor — Phase 2 (skeleton).
 *
 * Extends hello_supervisor with:
 *   - Filter covers openat, unlinkat, execve, connect, sendto.
 *   - Full response set: ALLOW (continue), DENY (return EPERM),
 *     KILL (kill target — reserved for future high-severity).
 *   - Placeholder policy that hardcodes a rule until the envelope
 *     loader lands in phase 2c: DENY any openat whose path starts
 *     with "/tmp/.deny_me", ALLOW everything else.
 *
 * Structure:
 *   - install_seccomp_filter(): builds a cBPF program that returns
 *     USER_NOTIF for the 5 tracked syscalls, ALLOW for everything else.
 *   - resolve_syscall_args(): reads path / argv / sockaddr from
 *     /proc/<pid>/mem depending on which syscall fired.
 *   - policy_decide(): stub policy (hardcoded for phase 2a/b).
 *   - notif_allow() / notif_deny(): the two response paths.
 *   - run_supervisor(): main loop.
 *
 * Once the envelope loader (phase 2c) lands, policy_decide() will
 * consult the envelope's paths/hosts/binaries.
 *
 * Build: make envelope_supervisor
 * Run:   ./envelope_supervisor <target_binary> [args...]
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
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

#include "policy_engine.h"
#include "target_reader.h"
#include "argv_tokenize.h"

/* Global envelope loaded at startup. Consulted from policy_decide(). */
static envelope_t g_env;
static bool g_env_loaded = false;

/* Harness bootstrap: the FIRST execve we see is the launch of the
 * target agent binary, not an attack. Envelopes don't need to list
 * the agent's own launch path in allow_binaries. */
static bool g_first_execve_seen = false;

/* Noise-floor prefixes for reads — Python/glibc bootstrap, always allow. */
static const char *NOISE_FLOOR_PREFIXES[] = {
    "/etc/", "/usr/", "/lib/", "/lib64/",
    "/proc/", "/sys/", "/dev/", "/System/", "/opt/",
    "/root/", "/var/lib/", "/run/", "/tmp/",  /* /tmp reads only */
    NULL,
};

static bool is_noise_floor_read(const char *path) {
    if (!path) return false;
    for (size_t i = 0; NOISE_FLOOR_PREFIXES[i]; ++i) {
        if (strncmp(path, NOISE_FLOOR_PREFIXES[i],
                    strlen(NOISE_FLOOR_PREFIXES[i])) == 0) {
            return true;
        }
    }
    return false;
}

/* Directly invoke the seccomp() syscall — glibc doesn't expose it. */
static int sys_seccomp(unsigned int op, unsigned int flags, void *args) {
    errno = 0;
    return (int)syscall(SYS_seccomp, op, flags, args);
}

/* ---------------- seccomp filter ---------------- */

/*
 * Build a filter that returns SECCOMP_RET_USER_NOTIF for the syscalls
 * our envelope cares about, and ALLOW for everything else.
 *
 * BPF cBPF for seccomp uses an accumulator model:
 *   BPF_LD ABS <offset>   → load word from seccomp_data at offset
 *   BPF_JMP JEQ K jt jf   → if A == K jump jt, else jump jf
 *   BPF_RET K             → return K
 *
 * We check architecture first (guard against 32-bit personality),
 * then dispatch on syscall number.
 */
static int install_seccomp_filter(void) {
    /* The list of syscalls we intercept. */
    const struct {
        unsigned int nr;
    } notified[] = {
        { SYS_openat   },
        { SYS_unlinkat },
        { SYS_execve   },
        { SYS_connect  },
        { SYS_sendto   },
    };
    const size_t N = sizeof(notified) / sizeof(notified[0]);

    /* Filter shape:
     *   arch check (3 insns)
     *   load nr    (1 insn)
     *   per-syscall: JEQ nr, notify, [continue]  → 2 insns each
     *   default: ALLOW (1 insn)
     *
     * Total: 4 + 2*N + 1
     */
    size_t nfilter = 4 + 2 * N + 1;
    struct sock_filter *f = calloc(nfilter, sizeof(*f));
    if (!f) { perror("calloc"); return -1; }

    size_t k = 0;
    /* Load arch */
    f[k++] = (struct sock_filter)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (offsetof(struct seccomp_data, arch)));
    /* If arch != x86_64, kill (defensive; we only support this arch) */
    f[k++] = (struct sock_filter)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
    f[k++] = (struct sock_filter)
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    /* Load syscall nr */
    f[k++] = (struct sock_filter)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (offsetof(struct seccomp_data, nr)));

    /* For each tracked syscall: if nr == it, return USER_NOTIF. */
    for (size_t i = 0; i < N; ++i) {
        f[k++] = (struct sock_filter)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, notified[i].nr, 0, 1);
        f[k++] = (struct sock_filter)
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
    }

    /* Default: allow. */
    f[k++] = (struct sock_filter)
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    struct sock_fprog prog = {
        .len = (unsigned short)nfilter,
        .filter = f,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        free(f);
        return -1;
    }
    int fd = sys_seccomp(SECCOMP_SET_MODE_FILTER,
                          SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (fd < 0) perror("seccomp(SET_MODE_FILTER)");
    free(f);
    return fd;
}

/* ---------------- fd-passing between child and parent ---------------- */

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
    if (sendmsg(sock, &msg, 0) < 0) { perror("sendmsg"); return -1; }
    return 0;
}

static int recv_fd(int sock) {
    char dummy;
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    char ctrl[CMSG_SPACE(sizeof(int))];
    memset(ctrl, 0, sizeof(ctrl));
    struct msghdr msg = {
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = ctrl, .msg_controllen = sizeof(ctrl),
    };
    if (recvmsg(sock, &msg, 0) < 0) { perror("recvmsg"); return -1; }
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (!c || c->cmsg_type != SCM_RIGHTS) {
        fprintf(stderr, "recv_fd: no fd in cmsg\n");
        return -1;
    }
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof(int));
    return fd;
}

/* Note: reading target memory is now in target_reader.c. Provide a
 * thin wrapper for callers that use the old signature. */
static ssize_t read_target_path(pid_t pid, unsigned long long addr,
                                 char *buf, size_t buf_size) {
    return target_read_string(pid, addr, buf, buf_size);
}

/* ---------------- policy stub ---------------- */

static const char *syscall_name(int nr);

/* openat flags — write intent */
#define O_ACCMODE_LOCAL   0x0003
#define O_WRONLY_LOCAL    0x0001
#define O_RDWR_LOCAL      0x0002

typedef enum { DECISION_ALLOW, DECISION_DENY } decision_t;

/*
 * Envelope-driven policy. Consults g_env for each syscall.
 *
 * openat:   check path against read_paths (or write_paths if write intent).
 *           Reads under noise-floor prefixes always allow.
 * unlinkat: check against delete_paths.
 * execve:   check binary against allow_binaries (allow_spawn gate first).
 * connect:  gate on allow_egress. (host check requires sockaddr reader —
 *           lands in phase 2d.)
 * sendto:   same as connect.
 *
 * If g_env is not loaded, default is ALLOW for all (observation mode).
 */
static decision_t policy_decide(const struct seccomp_notif *req,
                                 const char *description,
                                 const char *resolved_path) {
    (void)description;
    if (!g_env_loaded) return DECISION_ALLOW;

    int nr = req->data.nr;
    unsigned long long flags_arg;

    if (nr == SYS_openat) {
        if (!resolved_path || !resolved_path[0]) return DECISION_ALLOW;
        flags_arg = req->data.args[2];
        bool write_intent = ((flags_arg & O_ACCMODE_LOCAL) == O_WRONLY_LOCAL)
                          || ((flags_arg & O_ACCMODE_LOCAL) == O_RDWR_LOCAL);
        if (write_intent) {
            if (path_matches_any(resolved_path, &g_env.write_paths))
                return DECISION_ALLOW;
            return DECISION_DENY;
        } else {
            if (is_noise_floor_read(resolved_path))
                return DECISION_ALLOW;
            if (path_matches_any(resolved_path, &g_env.read_paths))
                return DECISION_ALLOW;
            return DECISION_DENY;
        }
    }

    if (nr == SYS_unlinkat) {
        if (!resolved_path || !resolved_path[0]) return DECISION_ALLOW;
        if (path_matches_any(resolved_path, &g_env.delete_paths))
            return DECISION_ALLOW;
        return DECISION_DENY;
    }

    if (nr == SYS_execve) {
        /* Bootstrap allowance: the very first execve is the launch of
         * the target agent binary from our supervisor. Treat it as
         * harness setup and always allow. Subsequent execves are
         * subject to envelope policy. */
        if (!g_first_execve_seen) {
            g_first_execve_seen = true;
            return DECISION_ALLOW;
        }
        if (!g_env.allow_spawn) return DECISION_DENY;
        if (!resolved_path || !resolved_path[0]) return DECISION_ALLOW;
        if (!binary_matches_any(resolved_path, &g_env.allow_binaries))
            return DECISION_DENY;

        /* v6a rule: check argv content. Read argv, extract path/host
         * tokens, each must be covered by envelope's positive surface. */
        char **argv = NULL;
        size_t n_argv = 0;
        if (target_read_argv((pid_t)req->pid, req->data.args[1],
                              &argv, &n_argv) < 0) {
            /* Failed to read argv — conservative: allow (mirrors current
             * behavior when we can't inspect). */
            return DECISION_ALLOW;
        }
        tokens_t paths, hosts;
        tokens_init(&paths);
        tokens_init(&hosts);
        argv_extract_tokens(argv, n_argv, &paths, &hosts);

        decision_t verdict = DECISION_ALLOW;
        for (size_t i = 0; i < paths.n && verdict == DECISION_ALLOW; ++i) {
            /* Path in argv must be covered by read/write/delete paths.
             * (Skip the binary path itself.) */
            if (strcmp(paths.items[i], resolved_path) == 0) continue;
            bool covered = path_matches_any(paths.items[i], &g_env.read_paths)
                        || path_matches_any(paths.items[i], &g_env.write_paths)
                        || path_matches_any(paths.items[i], &g_env.delete_paths);
            if (!covered) {
                fprintf(stderr, "[supervisor]   execve argv path OUT: %s\n",
                        paths.items[i]);
                verdict = DECISION_DENY;
            }
        }
        for (size_t i = 0; i < hosts.n && verdict == DECISION_ALLOW; ++i) {
            if (!host_matches_any(hosts.items[i], &g_env.allow_hosts)) {
                fprintf(stderr, "[supervisor]   execve argv host OUT: %s\n",
                        hosts.items[i]);
                verdict = DECISION_DENY;
            }
        }
        tokens_free(&paths);
        tokens_free(&hosts);
        target_free_argv(argv, n_argv);
        return verdict;
    }

    if (nr == SYS_connect || nr == SYS_sendto) {
        if (!g_env.allow_egress) return DECISION_DENY;
        /* Try to read sockaddr for host check. args[1]=sockaddr,
         * args[2]=addrlen for both connect and sendto. */
        unsigned long long sa_addr = req->data.args[1];
        size_t sa_len;
        if (nr == SYS_connect) {
            sa_len = (size_t)req->data.args[2];
        } else {
            /* sendto(fd, buf, len, flags, sockaddr, addrlen) → args[4], [5] */
            sa_addr = req->data.args[4];
            sa_len = (size_t)req->data.args[5];
        }
        if (sa_addr == 0 || sa_len == 0 || sa_len > 128) return DECISION_ALLOW;

        char sa_buf[128];
        if (target_read_sockaddr((pid_t)req->pid, sa_addr, sa_len,
                                   sa_buf, sizeof(sa_buf)) < 0) {
            return DECISION_ALLOW;
        }
        char host[64];
        uint16_t port = 0;
        if (sockaddr_extract_host_port(sa_buf, sa_len,
                                         host, sizeof(host), &port) < 0) {
            /* AF_UNIX or unrecognized — allow (not our threat model) */
            return DECISION_ALLOW;
        }
        /* Loopback is always OK regardless of allow_hosts. */
        if (strcmp(host, "127.0.0.1") == 0 || strcmp(host, "::1") == 0)
            return DECISION_ALLOW;
        if (host_matches_any(host, &g_env.allow_hosts))
            return DECISION_ALLOW;
        fprintf(stderr, "[supervisor]   %s host OUT: %s:%u\n",
                syscall_name(nr), host, port);
        return DECISION_DENY;
    }

    /* Unknown syscall — shouldn't happen given our filter, but allow. */
    return DECISION_ALLOW;
}

/* ---------------- notif responses ---------------- */

static int notif_allow(int notif_fd, __u64 id) {
    struct seccomp_notif_resp resp = {
        .id = id, .val = 0, .error = 0,
        .flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
        if (errno != ENOENT) perror("SECCOMP_IOCTL_NOTIF_SEND(allow)");
        return -1;
    }
    return 0;
}

static int notif_deny(int notif_fd, __u64 id, int errno_val) {
    struct seccomp_notif_resp resp = {
        .id = id, .val = 0, .error = -errno_val, .flags = 0,
    };
    if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
        if (errno != ENOENT) perror("SECCOMP_IOCTL_NOTIF_SEND(deny)");
        return -1;
    }
    return 0;
}

/* ---------------- main loop ---------------- */

static const char *syscall_name(int nr) {
    switch (nr) {
        case SYS_openat:   return "openat";
        case SYS_unlinkat: return "unlinkat";
        case SYS_execve:   return "execve";
        case SYS_connect:  return "connect";
        case SYS_sendto:   return "sendto";
        default:           return "unknown";
    }
}

static int run_supervisor(int notif_fd) {
    struct seccomp_notif req;
    unsigned long total = 0, denied = 0;
    for (;;) {
        memset(&req, 0, sizeof(req));
        if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOENT) {
                fprintf(stderr, "[supervisor] target exited "
                        "(%lu intercepted, %lu denied)\n", total, denied);
                return 0;
            }
            perror("SECCOMP_IOCTL_NOTIF_RECV");
            return -1;
        }
        total++;

        /* Path arg location by syscall:
         *   openat(dfd, pathname, flags, mode)  → args[1]
         *   unlinkat(dfd, pathname, flags)      → args[1]
         *   execve(pathname, argv, envp)        → args[0]
         *   connect / sendto → sockaddr, no path (phase 2d handles those)
         */
        char resolved[4096] = {0};
        int nr = req.data.nr;
        if (nr == SYS_openat || nr == SYS_unlinkat) {
            read_target_path((pid_t)req.pid, req.data.args[1],
                              resolved, sizeof(resolved));
        } else if (nr == SYS_execve) {
            read_target_path((pid_t)req.pid, req.data.args[0],
                              resolved, sizeof(resolved));
        }

        char logbuf[4200];
        snprintf(logbuf, sizeof(logbuf), "%s: %s",
                 syscall_name(nr), resolved[0] ? resolved : "(no path)");

        decision_t d = policy_decide(&req, logbuf, resolved);
        const char *verdict = (d == DECISION_DENY) ? "DENY" : "ALLOW";
        fprintf(stderr, "[supervisor] pid=%d %s [%s]\n",
                req.pid, logbuf, verdict);

        int rc;
        if (d == DECISION_DENY) {
            denied++;
            rc = notif_deny(notif_fd, req.id, EPERM);
        } else {
            rc = notif_allow(notif_fd, req.id);
        }
        if (rc < 0) {
            /* Non-fatal: might be ENOENT because target moved on. */
            continue;
        }
    }
}

/* ---------------- main ---------------- */

int main(int argc, char **argv) {
    const char *envelope_path = NULL;
    int argi = 1;

    if (argc >= 3 && strcmp(argv[argi], "--envelope") == 0) {
        envelope_path = argv[argi + 1];
        argi += 2;
    }

    if (argi >= argc) {
        fprintf(stderr, "usage: %s [--envelope <path>] <target_binary> [args...]\n",
                argv[0]);
        return 2;
    }

    if (envelope_path) {
        if (envelope_load(envelope_path, &g_env) < 0) {
            fprintf(stderr, "[supervisor] failed to load envelope %s\n",
                    envelope_path);
            return 1;
        }
        g_env_loaded = true;
        fprintf(stderr, "[supervisor] envelope loaded: read_paths=%zu "
                "write_paths=%zu delete_paths=%zu "
                "allow_binaries=%zu allow_spawn=%d allow_egress=%d\n",
                g_env.read_paths.n, g_env.write_paths.n,
                g_env.delete_paths.n, g_env.allow_binaries.n,
                g_env.allow_spawn, g_env.allow_egress);
    } else {
        fprintf(stderr, "[supervisor] no envelope — observation mode "
                "(all syscalls allowed)\n");
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
        /* Child: install filter, pass fd to parent, exec target. */
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
        execvp(argv[argi], &argv[argi]);
        perror("execvp");
        _exit(127);
    }

    /* Parent: receive fd, run supervisor loop, wait for child. */
    close(sv[1]);
    int notif_fd = recv_fd(sv[0]);
    close(sv[0]);
    if (notif_fd < 0) {
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
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "[supervisor] target killed by signal %d\n",
                WTERMSIG(status));
    }
    close(notif_fd);
    if (g_env_loaded) envelope_free(&g_env);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
