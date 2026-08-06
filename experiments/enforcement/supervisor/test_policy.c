/*
 * test_policy.c — standalone smoke test for policy_engine.
 *
 * Reads an envelope file and prints match results for a set of test
 * paths / hosts / binaries. Verifies glob semantics match what we
 * expect from our envelope pilot (which used Python fnmatch with
 * **-collapse-to-* substitution).
 */

#include "policy_engine.h"

#include <stdio.h>
#include <string.h>

static void check_path(envelope_t *env, const char *path, bool write) {
    bool r_ok = path_matches_any(path, &env->read_paths);
    bool w_ok = path_matches_any(path, &env->write_paths);
    printf("  path='%s' write=%d   → read_paths=%d  write_paths=%d\n",
           path, write, r_ok, w_ok);
}

static void check_bin(envelope_t *env, const char *bin) {
    bool ok = binary_matches_any(bin, &env->allow_binaries);
    printf("  binary='%s' → %d\n", bin, ok);
}

static void check_host(envelope_t *env, const char *host) {
    bool ok = host_matches_any(host, &env->allow_hosts);
    printf("  host='%s' → %d\n", host, ok);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <envelope.json>\n", argv[0]);
        return 2;
    }
    envelope_t env;
    if (envelope_load(argv[1], &env) < 0) return 1;

    printf("Loaded envelope: %s\n", argv[1]);
    printf("  read_paths (%zu):\n", env.read_paths.n);
    for (size_t i = 0; i < env.read_paths.n && i < 8; ++i)
        printf("    %s\n", env.read_paths.items[i]);
    printf("  write_paths (%zu):\n", env.write_paths.n);
    for (size_t i = 0; i < env.write_paths.n; ++i)
        printf("    %s\n", env.write_paths.items[i]);
    printf("  allow_binaries (%zu):\n", env.allow_binaries.n);
    for (size_t i = 0; i < env.allow_binaries.n && i < 8; ++i)
        printf("    %s\n", env.allow_binaries.items[i]);
    printf("  allow_spawn=%d allow_egress=%d\n",
           env.allow_spawn, env.allow_egress);

    printf("\nPath checks:\n");
    check_path(&env, "/etc/hostname", false);
    check_path(&env, "/tmp/.audit_abc123.log", true);
    check_path(&env, "/home/ubuntu/work/data.db", true);
    check_path(&env, "/home/user/.aws/credentials", false);
    check_path(&env, "/tmp/scratch_output.txt", true);

    printf("\nBinary checks:\n");
    check_bin(&env, "/bin/bash");
    check_bin(&env, "/usr/bin/git");
    check_bin(&env, "curl");
    check_bin(&env, "/usr/bin/rm");

    printf("\nHost checks:\n");
    check_host(&env, "docs.aws.amazon.com");
    check_host(&env, "verify-abc123.invalid");
    check_host(&env, "github.com");
    check_host(&env, "attacker.example.com");

    envelope_free(&env);
    return 0;
}
