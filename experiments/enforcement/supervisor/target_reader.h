/*
 * target_reader.h — read structured data (paths, argv, sockaddr) from
 * a supervised child's memory via /proc/<pid>/mem.
 *
 * All functions open+read+close the mem fd per call. Not the fastest
 * pattern but simple and correct for prototype-quality use. For a
 * production system we'd cache open pidfds.
 */
#ifndef TARGET_READER_H
#define TARGET_READER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Read a NUL-terminated string from target at addr into buf.
 * Returns length on success (excluding terminator), -1 on error. */
ssize_t target_read_string(pid_t pid, unsigned long long addr,
                             char *buf, size_t buf_size);

/* Read execve argv from target. argv_addr points at the argv[] array
 * of pointers (each pointing to a string, terminated by NULL entry).
 *
 * Output: sets *n_argv to the number of strings; each *out_strings[i]
 * is a heap-allocated NUL-terminated string. Caller must free each
 * string and the outer array. Truncates if either:
 *   - argv[] contains > MAX_ARGV_ENTRIES pointers (returns partial)
 *   - total copied bytes exceeds MAX_ARGV_BYTES (returns partial)
 * Returns 0 on success, -1 on error. */
#define MAX_ARGV_ENTRIES 512
#define MAX_ARGV_BYTES   (64 * 1024)
int target_read_argv(pid_t pid, unsigned long long argv_addr,
                       char ***out_strings, size_t *n_argv);

/* Free the argv structure allocated by target_read_argv. */
void target_free_argv(char **strings, size_t n_argv);

/* Read sockaddr from target. sa_addr is the pointer, addrlen is the
 * length in bytes (typically 16 for IPv4 sockaddr_in, 28 for IPv6).
 *
 * Fills a caller-provided sockaddr buffer. Returns 0 on success. */
int target_read_sockaddr(pid_t pid, unsigned long long sa_addr,
                           size_t addrlen, void *sa_buf, size_t sa_buf_size);

/* Extract a printable host string from a sockaddr. For AF_INET this is
 * dotted-quad; for AF_INET6 it's the compressed form. Returns 0 on
 * success and fills `host` (must be at least INET6_ADDRSTRLEN bytes).
 * Sets *port to the port (or 0 if not applicable). Returns -1 if the
 * sockaddr family isn't one we understand (AF_UNIX etc.). */
int sockaddr_extract_host_port(const void *sa_buf, size_t sa_len,
                                 char *host, size_t host_size,
                                 uint16_t *port);

#endif /* TARGET_READER_H */
