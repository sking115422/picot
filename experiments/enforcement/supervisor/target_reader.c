/*
 * target_reader.c — read strings/argv/sockaddr from a target process's
 * memory via /proc/<pid>/mem.
 *
 * We open the mem fd per call for simplicity. On heavy syscall rates
 * this is a real cost but not the bottleneck at prototype scale.
 */

#define _GNU_SOURCE
#include "target_reader.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Open /proc/<pid>/mem; caller closes. */
static int open_mem(pid_t pid) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/mem", pid);
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    return fd;
}

ssize_t target_read_string(pid_t pid, unsigned long long addr,
                             char *buf, size_t buf_size) {
    if (!buf || buf_size == 0) return -1;
    int fd = open_mem(pid);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, buf, buf_size - 1, (off_t)addr);
    close(fd);
    if (n < 0) return -1;
    for (ssize_t i = 0; i < n; ++i) {
        if (buf[i] == '\0') return i;
    }
    buf[n] = '\0';
    return n;
}

int target_read_argv(pid_t pid, unsigned long long argv_addr,
                       char ***out_strings, size_t *n_argv) {
    if (!out_strings || !n_argv) return -1;
    *out_strings = NULL;
    *n_argv = 0;
    if (argv_addr == 0) return 0;  /* NULL argv */

    int fd = open_mem(pid);
    if (fd < 0) return -1;

    /* Read the argv[] array of pointers, one at a time. Stop at NULL or
       when we hit the limit. */
    unsigned long long ptrs[MAX_ARGV_ENTRIES];
    size_t n = 0;
    while (n < MAX_ARGV_ENTRIES) {
        unsigned long long p;
        ssize_t r = pread(fd, &p, sizeof(p),
                          (off_t)(argv_addr + n * sizeof(unsigned long long)));
        if (r != (ssize_t)sizeof(p)) {
            /* Can't read further — cap here */
            break;
        }
        if (p == 0) break;
        ptrs[n++] = p;
    }

    /* Now read each string. Bound total bytes. */
    char **strs = calloc(n, sizeof(char *));
    if (!strs) { close(fd); return -1; }

    size_t total_bytes = 0;
    size_t collected = 0;
    for (size_t i = 0; i < n; ++i) {
        if (total_bytes >= MAX_ARGV_BYTES) break;
        char tmp[4096];
        size_t remaining = MAX_ARGV_BYTES - total_bytes;
        size_t chunk = sizeof(tmp) < remaining ? sizeof(tmp) : remaining;
        ssize_t r = pread(fd, tmp, chunk - 1, (off_t)ptrs[i]);
        if (r < 0) continue;
        /* NUL-terminate at first null or at end */
        size_t slen = r;
        for (ssize_t k = 0; k < r; ++k) {
            if (tmp[k] == '\0') { slen = k; break; }
        }
        tmp[slen] = '\0';
        char *s = strdup(tmp);
        if (!s) break;
        strs[collected++] = s;
        total_bytes += slen + 1;
    }
    close(fd);

    /* Realloc-down to actual size */
    if (collected == 0) {
        free(strs);
        strs = NULL;
    } else if (collected < n) {
        char **shrunk = realloc(strs, collected * sizeof(char *));
        if (shrunk) strs = shrunk;
    }
    *out_strings = strs;
    *n_argv = collected;
    return 0;
}

void target_free_argv(char **strings, size_t n_argv) {
    if (!strings) return;
    for (size_t i = 0; i < n_argv; ++i) free(strings[i]);
    free(strings);
}

int target_read_sockaddr(pid_t pid, unsigned long long sa_addr,
                           size_t addrlen, void *sa_buf, size_t sa_buf_size) {
    if (!sa_buf || sa_buf_size == 0) return -1;
    if (addrlen == 0 || addrlen > sa_buf_size) return -1;
    int fd = open_mem(pid);
    if (fd < 0) return -1;
    ssize_t r = pread(fd, sa_buf, addrlen, (off_t)sa_addr);
    close(fd);
    if (r != (ssize_t)addrlen) return -1;
    return 0;
}

int sockaddr_extract_host_port(const void *sa_buf, size_t sa_len,
                                 char *host, size_t host_size,
                                 uint16_t *port) {
    if (!sa_buf || !host || host_size == 0) return -1;
    if (sa_len < sizeof(sa_family_t)) return -1;

    sa_family_t fam;
    memcpy(&fam, sa_buf, sizeof(fam));

    if (fam == AF_INET && sa_len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in4 = sa_buf;
        if (!inet_ntop(AF_INET, &in4->sin_addr, host, host_size))
            return -1;
        if (port) *port = ntohs(in4->sin_port);
        return 0;
    }
    if (fam == AF_INET6 && sa_len >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *in6 = sa_buf;
        if (!inet_ntop(AF_INET6, &in6->sin6_addr, host, host_size))
            return -1;
        if (port) *port = ntohs(in6->sin6_port);
        return 0;
    }
    /* AF_UNIX, AF_NETLINK, others — no host to report */
    return -1;
}
