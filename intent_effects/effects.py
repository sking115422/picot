"""Convert argument-bearing syscall events into semantic OS effects."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from pathlib import PurePosixPath
from typing import Any, Iterable


SCHEMA_VERSION = "picot.semantic-effects.v1"

_CREDENTIAL_PATTERNS = (
    re.compile(r"/(?:\.ssh|\.gnupg|\.aws|\.azure|\.kube)(?:/|$)"),
    re.compile(r"/(?:credentials?|secrets?|tokens?)(?:[-_.\/]|$)", re.IGNORECASE),
    re.compile(r"/(?:\.netrc|\.npmrc|\.pypirc|id_rsa|id_ed25519)(?:$|\.)"),
    re.compile(r"/(?:\.api_key|\.oauth_token|\.access_token|\.refresh_token)$", re.IGNORECASE),
    re.compile(r"/(?:etc/shadow|etc/gshadow)$"),
)
_PERSISTENCE_PATTERNS = (
    re.compile(r"/(?:\.bashrc|\.zshrc|\.profile|\.bash_profile)$"),
    re.compile(r"/(?:\.config/systemd/user|\.config/autostart|\.ssh/authorized_keys)(?:/|$)"),
    re.compile(r"/(?:etc/cron|var/spool/cron|etc/systemd/system)(?:/|$)"),
)

_DYNAMIC_COMPONENT = re.compile(
    r"(?:[0-9a-f]{8,}|[0-9]{6,}|[0-9a-f]{8}-[0-9a-f-]{20,})",
    re.IGNORECASE,
)


def _normalize_component(component: str) -> str:
    normalized = _DYNAMIC_COMPONENT.sub("*", component)
    normalized = re.sub(r"(?:^|[-_.])[0-9]{3,}(?=$|[-_.])", "-*", normalized)
    return normalized or "*"


def abstract_path(path: str, semantic_class: str) -> str:
    """Map a concrete path to a stable, enforceable resource scope."""
    if not path.startswith("/"):
        first = path.split("/", 1)[0]
        return f"$RELATIVE/{_normalize_component(first)}/**"

    if path == "/workspace" or path.startswith("/workspace/"):
        suffix = path[len("/workspace") :]
        return "$PROJECT" + suffix
    if path == "/work" or path.startswith("/work/"):
        suffix = path[len("/work") :]
        return "$PROJECT" + suffix
    if path == "/home/ubuntu/work" or path.startswith("/home/ubuntu/work/"):
        suffix = path[len("/home/ubuntu/work") :]
        return "$PROJECT" + suffix

    home_prefix = None
    for prefix in ("/home/ubuntu", "/root"):
        if path == prefix or path.startswith(prefix + "/"):
            home_prefix = prefix
            break
    if home_prefix:
        relative = path[len(home_prefix) :].lstrip("/")
        parts = relative.split("/") if relative else []
        normalized_parts = [_normalize_component(part) for part in parts]
        if semantic_class == "credential":
            root = normalized_parts[0] if normalized_parts else "*"
            return f"$HOME/{root}/**"
        if semantic_class == "persistence":
            return "$HOME/" + "/".join(normalized_parts)
        if semantic_class in {"runtime_cache", "user_config"}:
            depth = 2 if len(normalized_parts) >= 2 else len(normalized_parts)
            return "$HOME/" + "/".join(normalized_parts[:depth]) + "/**"
        return "$HOME/" + "/".join(normalized_parts)

    parts = list(PurePosixPath(path).parts)
    if semantic_class == "runtime_library":
        if path.startswith("/usr/local/lib/"):
            return "/usr/local/lib/**"
        if path.startswith("/usr/lib/"):
            return "/usr/lib/**"
        if path.startswith("/lib64/"):
            return "/lib64/**"
        return "/lib/**"
    if semantic_class == "temporary":
        root = "/var/tmp" if path.startswith("/var/tmp/") else "/tmp"
        relative = path[len(root) :].lstrip("/")
        first = _normalize_component(relative.split("/", 1)[0]) if relative else "*"
        return f"{root}/{first}/**"
    if semantic_class == "kernel_or_device":
        root = parts[1] if len(parts) > 1 else "*"
        if root in {"proc", "sys"}:
            return f"/{root}/**"
        second = _normalize_component(parts[2]) if len(parts) > 2 else "*"
        return f"/dev/{second}"
    if semantic_class == "system_config":
        first = _normalize_component(parts[2]) if len(parts) > 2 else "*"
        return f"/etc/{first}/**" if len(parts) > 3 else f"/etc/{first}"
    if semantic_class == "other_absolute":
        first = _normalize_component(parts[1]) if len(parts) > 1 else "*"
        second = _normalize_component(parts[2]) if len(parts) > 2 else None
        return f"/{first}/{second}/**" if second else f"/{first}/**"
    return _DYNAMIC_COMPONENT.sub("*", path)


def classify_path(path: str) -> tuple[str, str, str]:
    """Return ``(semantic_class, role_hint, risk)`` for a Linux path."""
    if not path.startswith("/"):
        return "relative_or_unresolved", "unknown", "low"
    if any(pattern.search(path) for pattern in _PERSISTENCE_PATTERNS):
        return "persistence", "sensitive", "critical"
    if any(pattern.search(path) for pattern in _CREDENTIAL_PATTERNS):
        return "credential", "sensitive", "critical"
    if path.startswith(("/workspace/", "/home/ubuntu/work/", "/work/")) or path in {"/workspace", "/work"}:
        return "project", "task_facing", "medium"
    if path.startswith(("/usr/lib/", "/usr/local/lib/", "/lib/", "/lib64/", "/opt/hostedtoolcache/")):
        return "runtime_library", "runtime_dependency", "low"
    if path.startswith(("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")):
        return "system_executable", "runtime_dependency", "low"
    if path.startswith(("/etc/", "/etc")):
        return "system_config", "runtime_dependency", "medium"
    if path.startswith(("/proc/", "/sys/", "/dev/")):
        return "kernel_or_device", "runtime_dependency", "medium"
    if path.startswith(("/tmp/", "/var/tmp/")):
        return "temporary", "runtime_dependency", "low"
    if path.startswith(("/home/ubuntu/.cache/", "/root/.cache/", "/home/ubuntu/.local/", "/root/.local/")):
        return "runtime_cache", "runtime_dependency", "low"
    if path.startswith(("/home/ubuntu/.", "/root/.")):
        return "user_config", "task_or_runtime", "medium"
    if path.startswith(("/home/", "/root/")):
        return "user_data", "task_facing", "medium"
    return "other_absolute", "unknown", "medium"


def classify_network(address: str | None, unix_path: str | None) -> tuple[str, str, str]:
    if unix_path:
        return "local_ipc", "runtime_dependency", "low"
    if not address:
        return "network_unresolved", "unknown", "medium"
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "network_name", "task_facing", "medium"
    if ip.is_loopback:
        return "network_loopback", "runtime_dependency", "low"
    if ip in ipaddress.ip_network("192.0.2.0/24") or ip in ipaddress.ip_network("198.51.100.0/24") or ip in ipaddress.ip_network("203.0.113.0/24"):
        return "network_documentation", "sensitive", "high"
    if ip.is_private or ip.is_link_local:
        return "network_private", "task_or_runtime", "medium"
    return "network_public", "task_facing", "high"


def _path_effect(event: dict[str, Any], verb: str, path: str, destination: str | None = None) -> dict[str, Any]:
    semantic_class, role_hint, risk = classify_path(path)
    if semantic_class == "persistence" and verb == "read":
        role_hint, risk = "runtime_dependency", "low"
    effect = {
        "family": "file",
        "verb": verb,
        "resource": abstract_path(path, semantic_class),
        "concrete_resource": path,
        "semantic_class": semantic_class,
        "role_hint": role_hint,
        "risk": risk,
        "pid": event["pid"],
        "timestamp": event["timestamp"],
        "syscall": event["syscall"],
        "success": event.get("return_value") is None or event.get("return_value", -1) >= 0,
    }
    if destination:
        destination_class, _, _ = classify_path(destination)
        effect["destination_resource"] = abstract_path(destination, destination_class)
        effect["concrete_destination_resource"] = destination
    return effect


def event_to_effect(event: dict[str, Any]) -> dict[str, Any] | None:
    syscall = event["syscall"]
    path = event.get("path")
    if syscall in {"open", "openat", "creat"} and path:
        if event.get("create_intent"):
            verb = "create_or_write"
        elif event.get("write_intent"):
            verb = "write"
        else:
            verb = "read"
        return _path_effect(event, verb, path)
    if syscall in {"unlink", "unlinkat", "rmdir"} and path:
        return _path_effect(event, "delete", path)
    if syscall in {"mkdir", "mkdirat"} and path:
        return _path_effect(event, "create_directory", path)
    if syscall in {"rename", "renameat", "renameat2"} and path:
        return _path_effect(event, "rename", path, event.get("destination_path"))
    if syscall in {"chmod", "fchmodat"} and path:
        return _path_effect(event, "change_permissions", path)
    if syscall == "execve" and path:
        semantic_class, role_hint, risk = classify_path(path)
        argv = event.get("argv") or []
        binary = PurePosixPath(path).name
        if binary in {"bash", "sh", "zsh", "dash", "python", "python3", "node", "perl", "ruby"}:
            risk = "high"
        return {
            "family": "process",
            "verb": "execute",
            "resource": abstract_path(path, semantic_class),
            "concrete_resource": path,
            "semantic_class": semantic_class,
            "role_hint": "task_or_runtime" if role_hint == "runtime_dependency" else role_hint,
            "risk": risk,
            "pid": event["pid"],
            "timestamp": event["timestamp"],
            "syscall": syscall,
            "success": event.get("return_value") is None or event.get("return_value", -1) >= 0,
            "argv_preview": argv[:12],
        }
    if syscall in {"connect", "bind"}:
        semantic_class, role_hint, risk = classify_network(event.get("address"), event.get("unix_path"))
        resource = event.get("unix_path") or event.get("address") or event.get("family") or "unresolved"
        if event.get("port") is not None and event.get("address"):
            resource = f"{event['address']}:{event['port']}"
        return {
            "family": "network",
            "verb": syscall,
            "resource": str(resource),
            "semantic_class": semantic_class,
            "role_hint": role_hint,
            "risk": risk,
            "pid": event["pid"],
            "timestamp": event["timestamp"],
            "syscall": syscall,
            "success": event.get("return_value") is None or event.get("return_value", -1) >= 0,
        }
    return None


def aggregate_effects(events: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw_count = 0
    modeled_count = 0
    effects: dict[tuple, dict[str, Any]] = {}
    raw_syscalls: Counter[str] = Counter()
    for event in events:
        raw_count += 1
        raw_syscalls[event["syscall"]] += 1
        effect = event_to_effect(event)
        if effect is None:
            continue
        modeled_count += 1
        key = (
            effect["family"],
            effect["verb"],
            effect["resource"],
            effect.get("destination_resource"),
            tuple(effect.get("argv_preview") or []),
        )
        existing = effects.get(key)
        if existing is None:
            existing = dict(effect)
            concrete_resource = existing.pop("concrete_resource", None)
            concrete_destination = existing.pop("concrete_destination_resource", None)
            if concrete_resource is not None:
                existing["example_resources"] = [concrete_resource]
            if concrete_destination is not None:
                existing["example_destination_resources"] = [concrete_destination]
            existing["count"] = 1
            existing["success_count"] = int(bool(effect["success"]))
            existing["failure_count"] = int(not effect["success"])
            existing["first_timestamp"] = effect.pop("timestamp")
            existing["last_timestamp"] = existing["first_timestamp"]
            existing.pop("timestamp", None)
            existing.pop("success", None)
            effects[key] = existing
        else:
            existing["count"] += 1
            existing["success_count"] += int(bool(effect["success"]))
            existing["failure_count"] += int(not effect["success"])
            existing["last_timestamp"] = effect["timestamp"]
            concrete_resource = effect.get("concrete_resource")
            examples = existing.setdefault("example_resources", [])
            if concrete_resource is not None and concrete_resource not in examples and len(examples) < 3:
                examples.append(concrete_resource)
            concrete_destination = effect.get("concrete_destination_resource")
            if concrete_destination is not None:
                destination_examples = existing.setdefault("example_destination_resources", [])
                if concrete_destination not in destination_examples and len(destination_examples) < 3:
                    destination_examples.append(concrete_destination)

    ordered = sorted(
        effects.values(),
        key=lambda effect: (
            effect["first_timestamp"],
            effect["family"],
            effect["verb"],
            effect["resource"],
        ),
    )
    family_counts = Counter(effect["family"] for effect in ordered)
    class_counts = Counter(effect["semantic_class"] for effect in ordered)
    role_counts = Counter(effect["role_hint"] for effect in ordered)
    return ordered, {
        "raw_event_count": raw_count,
        "modeled_event_count": modeled_count,
        "unique_effect_count": len(ordered),
        "raw_syscall_counts": dict(sorted(raw_syscalls.items())),
        "effect_family_counts": dict(sorted(family_counts.items())),
        "semantic_class_counts": dict(sorted(class_counts.items())),
        "role_hint_counts": dict(sorted(role_counts.items())),
    }
