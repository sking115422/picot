/*
 * policy_engine.h — envelope-driven policy for envelope_supervisor.
 *
 * Loads an envelope JSON at startup into a compact struct that
 * decision-time code can consult. Policy check functions accept
 * resolved syscall args (paths, hosts, binaries) and return
 * ALLOW or DENY.
 */
#ifndef POLICY_ENGINE_H
#define POLICY_ENGINE_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char **items;
    size_t n;
} pattern_list_t;

typedef struct {
    /* file_ops */
    pattern_list_t read_paths;
    pattern_list_t write_paths;
    pattern_list_t delete_paths;
    /* network */
    bool allow_egress;
    pattern_list_t allow_hosts;
    /* process */
    bool allow_spawn;
    pattern_list_t allow_binaries;
} envelope_t;

/* Load an envelope JSON file into `env`. Returns 0 on success, -1 on error.
 * env->allow_egress and allow_spawn default false; unspecified pattern lists
 * default to empty. */
int envelope_load(const char *path, envelope_t *env);

/* Free all owned memory. Safe to call on a zeroed struct. */
void envelope_free(envelope_t *env);

/* Match a path against a glob pattern list. Supports **, *, ?, [set].
 * Returns true iff `path` matches any pattern in `list`. */
bool path_matches_any(const char *path, const pattern_list_t *list);

/* Same for host allow-lists. Uses the same matcher. */
bool host_matches_any(const char *host, const pattern_list_t *list);

/* Match a binary against allow_binaries. Special semantics: match if
 * either the full path OR the basename equals a pattern (or matches
 * a glob). */
bool binary_matches_any(const char *path, const pattern_list_t *list);

#endif /* POLICY_ENGINE_H */
