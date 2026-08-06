/*
 * argv_tokenize.h — extract path-like and host-like tokens from an
 * argv array (or a shell-command string embedded in argv).
 *
 * C mirror of picot/experiments/envelope_pilot/ace_full/argv_tokenize.py.
 * Simplifications for prototype quality:
 *   - Paths: any token starting with '/' or '~/' or './' is a path.
 *   - Hosts: IPv4 (N.N.N.N) or hostname with a '.' and >=1 alpha char.
 *   - Shell decomposition: if a token looks like a shell command
 *     (contains a space AND at least one path-shape token when
 *     naively split), we shlex-split and recurse.
 */
#ifndef ARGV_TOKENIZE_H
#define ARGV_TOKENIZE_H

#include <stddef.h>

typedef struct {
    char **items;
    size_t n;
    size_t cap;
} tokens_t;

/* Initialize empty. */
void tokens_init(tokens_t *t);

/* Free contents. */
void tokens_free(tokens_t *t);

/* Add a token (copies the string). */
int tokens_push(tokens_t *t, const char *s);

/* Extract path-like tokens from argv and put into out_paths.
 * Extract host-like tokens into out_hosts. */
int argv_extract_tokens(char **argv, size_t n_argv,
                          tokens_t *out_paths, tokens_t *out_hosts);

#endif /* ARGV_TOKENIZE_H */
