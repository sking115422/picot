/*
 * argv_tokenize.c — C port of the argv tokenizer.
 *
 * Simpler than the Python version (no URL regex, no exhaustive shell
 * indicator list) but covers our corpus's attack shapes:
 *   - Absolute path: token starts with '/'
 *   - Home-relative: token starts with '~/'
 *   - Explicit relative: token starts with './' or '../'
 *   - IPv4: pattern N.N.N.N where each N is 0-255
 *   - Hostname: contains '.' and at least one alpha char, no '/', no space
 *
 * Shell decomposition: for tokens containing whitespace we run a simple
 * whitespace-split (no quoted-string handling — the corpus attacks
 * don't rely on shell quoting nuances). We deliberately DON'T use full
 * shlex because attacker inputs can be adversarial and we prefer
 * deterministic behavior on our real corpus over spec-compliance.
 */

#define _GNU_SOURCE
#include "argv_tokenize.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void tokens_init(tokens_t *t) {
    t->items = NULL;
    t->n = 0;
    t->cap = 0;
}

void tokens_free(tokens_t *t) {
    if (!t) return;
    for (size_t i = 0; i < t->n; ++i) free(t->items[i]);
    free(t->items);
    t->items = NULL;
    t->n = 0;
    t->cap = 0;
}

int tokens_push(tokens_t *t, const char *s) {
    if (t->n == t->cap) {
        size_t nc = t->cap ? t->cap * 2 : 16;
        char **np = realloc(t->items, nc * sizeof(char *));
        if (!np) return -1;
        t->items = np;
        t->cap = nc;
    }
    t->items[t->n] = strdup(s);
    if (!t->items[t->n]) return -1;
    t->n++;
    return 0;
}

/* Trim leading/trailing whitespace + trailing punctuation. */
static void trim(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == ',' || s[len - 1] == ';' ||
                        s[len - 1] == ')' || isspace((unsigned char)s[len-1]))) {
        s[--len] = '\0';
    }
    size_t start = 0;
    while (s[start] && isspace((unsigned char)s[start])) start++;
    if (start > 0) memmove(s, s + start, len - start + 1);
}

static bool token_is_path(const char *s) {
    if (!s || !*s) return false;
    if (strchr(s, ' ')) return false;  /* embedded space → not a single path */
    if (s[0] == '/') return true;
    if (s[0] == '~' && s[1] == '/') return true;
    if (s[0] == '.' && s[1] == '/') return true;
    if (s[0] == '.' && s[1] == '.' && s[2] == '/') return true;
    return false;
}

static bool is_ipv4(const char *s) {
    int a, b, c, d;
    char extra;
    if (sscanf(s, "%d.%d.%d.%d%c", &a, &b, &c, &d, &extra) != 4) return false;
    return a >= 0 && a <= 255 && b >= 0 && b <= 255 &&
           c >= 0 && c <= 255 && d >= 0 && d <= 255;
}

static bool token_is_hostname(const char *s) {
    if (!s || !*s) return false;
    /* No slash, no space, contains '.', at least one alpha */
    if (strchr(s, '/')) return false;
    if (strchr(s, ' ')) return false;
    if (!strchr(s, '.')) return false;
    bool has_alpha = false;
    for (const char *p = s; *p; ++p) {
        if (isalpha((unsigned char)*p)) { has_alpha = true; break; }
    }
    if (!has_alpha) return false;
    /* Reject strings starting with a digit and containing only digits+dots
       unless they're a valid IPv4 (handled separately). */
    return true;
}

/* Extract hostname from a URL-like token. Returns strdup'd host or NULL. */
static char *extract_url_host(const char *tok) {
    const char *scheme_end = strstr(tok, "://");
    if (!scheme_end) return NULL;
    const char *host_start = scheme_end + 3;
    /* Find end: next '/', ':', or end of string */
    const char *host_end = host_start;
    while (*host_end && *host_end != '/' && *host_end != ':' &&
           *host_end != '?' && *host_end != '#') {
        host_end++;
    }
    if (host_end == host_start) return NULL;
    size_t len = host_end - host_start;
    char *h = malloc(len + 1);
    if (!h) return NULL;
    memcpy(h, host_start, len);
    h[len] = '\0';
    return h;
}

/* Scan a single token. Add matching entries to paths/hosts. */
static void scan_token(const char *tok, tokens_t *paths, tokens_t *hosts) {
    if (!tok || !*tok) return;

    /* URL first (contains :// and a host) */
    char *url_host = extract_url_host(tok);
    if (url_host) {
        tokens_push(hosts, url_host);
        free(url_host);
        return;
    }

    /* Make a mutable copy so trim() can operate. */
    char *dup = strdup(tok);
    if (!dup) return;
    trim(dup);

    if (token_is_path(dup)) {
        tokens_push(paths, dup);
        free(dup);
        return;
    }
    if (is_ipv4(dup) || token_is_hostname(dup)) {
        tokens_push(hosts, dup);
        free(dup);
        return;
    }

    /* If token contains a space, split on whitespace and recurse.
       This handles `bash -c "ls /home/.../creds"` where the -c arg is
       one big string containing path tokens inside. */
    if (strchr(dup, ' ')) {
        char *save = NULL;
        char *tmp = strdup(dup);
        for (char *w = strtok_r(tmp, " \t\n", &save); w;
             w = strtok_r(NULL, " \t\n", &save)) {
            /* recurse — but don't recurse further into sub-tokens with spaces */
            scan_token(w, paths, hosts);
        }
        free(tmp);
    }
    free(dup);
}

/* De-duplicate a tokens_t in place (preserving first occurrence). */
static void tokens_dedup(tokens_t *t) {
    for (size_t i = 0; i < t->n; ++i) {
        for (size_t j = i + 1; j < t->n; ) {
            if (strcmp(t->items[i], t->items[j]) == 0) {
                free(t->items[j]);
                for (size_t k = j; k + 1 < t->n; ++k)
                    t->items[k] = t->items[k + 1];
                t->n--;
            } else {
                j++;
            }
        }
    }
}

int argv_extract_tokens(char **argv, size_t n_argv,
                          tokens_t *out_paths, tokens_t *out_hosts) {
    if (!out_paths || !out_hosts) return -1;
    for (size_t i = 0; i < n_argv; ++i) {
        scan_token(argv[i], out_paths, out_hosts);
    }
    tokens_dedup(out_paths);
    tokens_dedup(out_hosts);
    return 0;
}
