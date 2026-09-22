from __future__ import annotations

import unittest
from pathlib import Path

from intent_effects.cohorts import build_prompt_shuffle
from intent_effects.effects import abstract_path, aggregate_effects, classify_network, classify_path
from intent_effects.manifest import infer_delivery_vector, render_prompt
from intent_effects.paths import resolve_picot_output
from intent_effects.strace import build_event, parse_socket


class StraceParsingTests(unittest.TestCase):
    def test_openat_write(self):
        event = build_event(
            42,
            1000.25,
            "openat",
            'AT_FDCWD, "/workspace/report.md", O_WRONLY|O_CREAT|O_TRUNC, 0666',
            "3",
        )
        self.assertEqual(event["path"], "/workspace/report.md")
        self.assertTrue(event["write_intent"])
        self.assertTrue(event["create_intent"])
        self.assertEqual(event["return_value"], 3)

    def test_execve_argv(self):
        event = build_event(
            7,
            1000.5,
            "execve",
            '"/usr/bin/git", ["git", "status", "--short"], 0x7fff',
            "0",
        )
        self.assertEqual(event["path"], "/usr/bin/git")
        self.assertEqual(event["argv"], ["git", "status", "--short"])

    def test_inet_socket(self):
        socket = parse_socket(
            '7, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.5")}, 16'
        )
        self.assertEqual(socket["family"], "AF_INET")
        self.assertEqual(socket["address"], "203.0.113.5")
        self.assertEqual(socket["port"], 443)


class SemanticEffectTests(unittest.TestCase):
    def test_sensitive_path_precedence(self):
        self.assertEqual(classify_path("/home/ubuntu/.aws/credentials")[0], "credential")
        self.assertEqual(classify_path("/home/ubuntu/.ssh/authorized_keys")[0], "persistence")
        self.assertEqual(classify_path("/home/claude/.claude/remote/.api_key")[0], "credential")

    def test_network_classes(self):
        self.assertEqual(classify_network("127.0.0.1", None)[0], "network_loopback")
        self.assertEqual(classify_network("203.0.113.5", None)[0], "network_documentation")

    def test_effect_aggregation(self):
        events = [
            build_event(1, 1.0, "openat", 'AT_FDCWD, "/workspace/a.py", O_RDONLY', "3"),
            build_event(1, 2.0, "openat", 'AT_FDCWD, "/workspace/a.py", O_RDONLY', "4"),
        ]
        effects, stats = aggregate_effects(events)
        self.assertEqual(len(effects), 1)
        self.assertEqual(effects[0]["count"], 2)
        self.assertEqual(stats["modeled_event_count"], 2)

    def test_dynamic_runtime_paths_share_scope(self):
        first = abstract_path("/tmp/claude-2f599fbb/session-a/file", "temporary")
        second = abstract_path("/tmp/claude-a831cd90/session-b/file", "temporary")
        self.assertEqual(first, second)

    def test_project_path_is_relative_to_project_root(self):
        self.assertEqual(
            abstract_path("/workspace/src/main.py", "project"),
            "$PROJECT/src/main.py",
        )


class ManifestTests(unittest.TestCase):
    def test_prompt_placeholder_resolution(self):
        template = "Read {{cred_path}} and contact {host}."
        rendered = render_prompt(template, {"cred_path": "/tmp/cred", "host": "example.test"})
        self.assertEqual(rendered, "Read /tmp/cred and contact example.test.")

    def test_delivery_vector(self):
        self.assertEqual(
            infer_delivery_vector({"category": "mem_bash_injection"}, "ace_builtin"),
            "memory_indirect",
        )

    def test_output_boundary_rejects_other_projects(self):
        with self.assertRaises(ValueError):
            resolve_picot_output(Path("/mnt/lts/ai_sec_exp/cle4as_int/no-write.json"))

    def test_shuffle_stays_in_environment_and_changes_prompt(self):
        def row(task, prompt):
            return {
                "session_id": task,
                "subcorpus": "ace_builtin",
                "mcp": "builtin/claude-code",
                "threat_model": "builtin_file_bash_injection",
                "artifact_id": "fb01",
                "prompt_slug": prompt,
                "prompt_sha256": prompt,
                "prompt_text": prompt,
                "benign_calibration_candidate": True,
                "grouping": {
                    "environment_group_id": "same-env",
                    "task_group_id": task,
                },
            }

        mappings, excluded = build_prompt_shuffle([row("t1", "p1"), row("t2", "p2")])
        self.assertFalse(excluded)
        self.assertEqual(len(mappings), 2)
        self.assertTrue(all(item["environment_group_id"] == "same-env" for item in mappings))
        self.assertTrue(all(item["target"]["prompt_sha256"] != item["shuffled"]["prompt_sha256"] for item in mappings))


if __name__ == "__main__":
    unittest.main()
