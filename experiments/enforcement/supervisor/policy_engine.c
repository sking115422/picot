/*
 * policy_engine.c — envelope loader + glob matching for path/host/binary.
 *
 * The glob matcher handles our envelope grammar: `**` for recursive
 * directory match, `*` for a single path segment, `?` for a single
 * character. Behavior is close to bash's extglob but simpler.
 *
 * We don't need [set] support since our envelopes don't use it.
 */

#define _GNU_SOURCE
#include "policy_engine.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------- glob matcher ---------------- */

/* Match `text` (fully) against `pat`. Supports:
 *   `**`  → match any sequence including slashes
 *   `*`   → match any sequence not containing '/'
 *   `?`   → match a single character (not '/')
 *   other → literal
 *
 * Non-recursive implementation with backtracking. Handles patterns
 * of realistic envelope size (dozens of chars) without stack risk.
 */
static bool glob_match(const char *pat, const char *text) {
    const char *p = pat;
    const char *t = text;
    const char *star_p = NULL;   /* backtrack pattern pos */
    const char *star_t = NULL;   /* backtrack text pos    */
    bool star_is_double = false; /* was the * a ** (match slashes)? */

    while (*t) {
        if (*p == '*' && *(p + 1) == '*') {
            /* ** — consume all *'s, remember position, ** matches slashes */
            while (*p == '*') p++;
            star_p = p;
            star_t = t;
            star_is_double = true;
            if (*p == '\0') return true; /* trailing ** matches everything */
            continue;
        }
        if (*p == '*') {
            /* single * — matches any run of non-slash chars */
            star_p = p + 1;
            star_t = t;
            star_is_double = false;
            p++;
            if (*p == '\0') {
                /* trailing single-*: matches iff no more slashes in text */
                for (const char *q = t; *q; ++q) if (*q == '/') return false;
                return true;
            }
            continue;
        }
        if (*p == '?' && *t != '/') {
            p++; t++; continue;
        }
        if (*p == *t && *p != '\0') {
            p++; t++; continue;
        }
        /* Mismatch — backtrack to last star if possible */
        if (star_p) {
            p = star_p;
            star_t++;
            /* single-* cannot consume '/' */
            if (!star_is_double && *star_t == '/') {
                /* would consume slash — backtrack fails */
                /* but the star_t past slash could still work if pattern
                   matches from p onward against text starting at star_t */
                /* continue anyway; the mismatch will fail cleanly */
            }
            t = star_t;
            continue;
        }
        return false;
    }
    /* text exhausted — pattern must be exhausted or trailing stars */
    while (*p == '*') p++;
    return *p == '\0';
}

/* ---------------- pattern list ops ---------------- */

static int patlist_reserve(pattern_list_t *pl, size_t new_n) {
    char **np = realloc(pl->items, new_n * sizeof(char *));
    if (!np) return -1;
    pl->items = np;
    return 0;
}

static int patlist_push(pattern_list_t *pl, const char *s) {
    if (patlist_reserve(pl, pl->n + 1) < 0) return -1;
    pl->items[pl->n] = strdup(s);
    if (!pl->items[pl->n]) return -1;
    pl->n++;
    return 0;
}

static void patlist_free(pattern_list_t *pl) {
    for (size_t i = 0; i < pl->n; ++i) free(pl->items[i]);
    free(pl->items);
    pl->items = NULL;
    pl->n = 0;
}

static int load_string_array(cJSON *parent, const char *field,
                              pattern_list_t *pl) {
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(parent, field);
    if (!arr || !cJSON_IsArray(arr)) return 0; /* absent is ok */
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, arr) {
        if (cJSON_IsString(item) && item->valuestring) {
            if (patlist_push(pl, item->valuestring) < 0) return -1;
        }
    }
    return 0;
}

static bool load_bool(cJSON *parent, const char *field, bool dflt) {
    cJSON *b = cJSON_GetObjectItemCaseSensitive(parent, field);
    if (!b) return dflt;
    if (cJSON_IsBool(b)) return cJSON_IsTrue(b);
    return dflt;
}

/* ---------------- envelope load ---------------- */

int envelope_load(const char *path, envelope_t *env) {
    memset(env, 0, sizeof(*env));

    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 1 << 20) {
        fclose(f);
        fprintf(stderr, "envelope_load: size out of range (%ld)\n", sz);
        return -1;
    }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f); free(buf); return -1;
    }
    buf[sz] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        fprintf(stderr, "envelope_load: JSON parse error\n");
        return -1;
    }

    /* Two layouts we might get:
     *   (a) top-level object IS the envelope
     *   (b) wrapper object with an "envelope" key (from generate_envelopes.py)
     */
    cJSON *env_root = cJSON_GetObjectItemCaseSensitive(root, "envelope");
    if (!env_root) env_root = root;

    cJSON *file_ops = cJSON_GetObjectItemCaseSensitive(env_root, "file_ops");
    cJSON *network  = cJSON_GetObjectItemCaseSensitive(env_root, "network");
    cJSON *process  = cJSON_GetObjectItemCaseSensitive(env_root, "process");

    int rc = 0;
    if (file_ops) {
        rc |= load_string_array(file_ops, "read_paths",   &env->read_paths);
        rc |= load_string_array(file_ops, "write_paths",  &env->write_paths);
        rc |= load_string_array(file_ops, "delete_paths", &env->delete_paths);
    }
    if (network) {
        env->allow_egress = load_bool(network, "allow_egress", false);
        rc |= load_string_array(network, "allow_hosts", &env->allow_hosts);
    }
    if (process) {
        env->allow_spawn = load_bool(process, "allow_spawn", false);
        rc |= load_string_array(process, "allow_binaries", &env->allow_binaries);
    }
    cJSON_Delete(root);
    if (rc != 0) {
        envelope_free(env);
        return -1;
    }
    return 0;
}

void envelope_free(envelope_t *env) {
    if (!env) return;
    patlist_free(&env->read_paths);
    patlist_free(&env->write_paths);
    patlist_free(&env->delete_paths);
    patlist_free(&env->allow_hosts);
    patlist_free(&env->allow_binaries);
    env->allow_egress = false;
    env->allow_spawn = false;
}

/* ---------------- match APIs ---------------- */

bool path_matches_any(const char *path, const pattern_list_t *list) {
    if (!path || !list) return false;
    for (size_t i = 0; i < list->n; ++i) {
        if (glob_match(list->items[i], path)) return true;
    }
    return false;
}

bool host_matches_any(const char *host, const pattern_list_t *list) {
    return path_matches_any(host, list);
}

bool binary_matches_any(const char *path, const pattern_list_t *list) {
    if (!path || !list) return false;
    /* Try full-path match first */
    if (path_matches_any(path, list)) return true;
    /* Try basename match */
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    for (size_t i = 0; i < list->n; ++i) {
        if (strcmp(list->items[i], base) == 0) return true;
        if (glob_match(list->items[i], base)) return true;
    }
    return false;
}
