#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes
import dataclasses
import errno
import hashlib
import io
import ipaddress
import json
import os
import platform
import re
import secrets
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator, Mapping, Sequence, TextIO


RULE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{1,79}")


class ExitCode(IntEnum):
    PASS = 0
    POLICY_OR_CONTENT = 2
    TOOLING_OR_INPUT = 3
    APPROVAL = 4
    REMOTE_OR_PROTECTION = 5
    INCOMPLETE_SURFACE = 6


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Finding:
    rule_id: str
    classification: str
    path: str
    location: str
    message: str


@dataclass(frozen=True)
class ExactException:
    rule_id: str
    path: str
    sha256: str
    rationale: str
    agent_material: bool


@dataclass(frozen=True)
class Policy:
    schema_version: int
    repository: str
    public_branches: tuple[str, ...]
    public_tag_patterns: tuple[str, ...]
    public_email_patterns: tuple[str, ...]
    path_exceptions: tuple[ExactException, ...]
    synthetic_exceptions: tuple[ExactException, ...]
    ci_workflow: str
    ci_check: str
    protected_branches: tuple[str, ...]
    protected_tag_patterns: tuple[str, ...]
    manual_documents: tuple[str, ...]
    gitleaks_version: str


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


Runner = Callable[
    [Sequence[str], Path | None, Mapping[str, str] | None],
    CommandResult
]
ConfigParserRunner = Callable[
    [Sequence[str], Path | None, Mapping[str, str] | None, bytes],
    CommandResult
]


def _run_command(
    argv: Sequence[str],
    cwd: Path | None,
    env: Mapping[str, str] | None,
    input_data: bytes | None
) -> CommandResult:
    completed = subprocess.run(
        list(argv),
        cwd=os.fspath(cwd) if cwd else None,
        env=dict(env) if env else None,
        stdin=subprocess.DEVNULL if input_data is None else None,
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def run_command(
    argv: Sequence[str],
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None
) -> CommandResult:
    return _run_command(argv, cwd, env, None)


def run_config_parser(
    argv: Sequence[str],
    cwd: Path | None,
    env: Mapping[str, str] | None,
    input_data: bytes
) -> CommandResult:
    return _run_command(argv, cwd, env, input_data)


def hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate key: {key}")
        result[key] = value
    return result


def _keys(value: Mapping[str, object], allowed: set[str], context: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise PolicyError(f"{context} has unknown keys: {', '.join(unknown)}")


def _exact_path(value: object, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
        or re.match(r"^[A-Za-z]:", value)
        or _has_control_characters(value)
    ):
        raise PolicyError(f"{context} must be an exact repository path")
    parts = value.split("/")
    if (
        any(part in {"", ".", ".."} for part in parts)
        or any(char in value for char in "*?[]{}")
    ):
        raise PolicyError(f"{context} must be an exact repository path")
    return value


def _exceptions(values: object, context: str) -> tuple[ExactException, ...]:
    if not isinstance(values, list):
        raise PolicyError(f"{context} must be an array")
    parsed: list[ExactException] = []
    seen: set[ExactException] = set()
    for index, raw in enumerate(values):
        if not isinstance(raw, dict):
            raise PolicyError(f"{context}[{index}] must be an object")
        _keys(raw, {"rule_id", "path", "sha256", "rationale", "agent_material"}, context)
        digest = raw.get("sha256")
        rationale = raw.get("rationale")
        rule_id = raw.get("rule_id")
        agent_material = raw.get("agent_material")
        if (
            not isinstance(rule_id, str)
            or RULE_ID_PATTERN.fullmatch(rule_id) is None
        ):
            raise PolicyError(f"{context}[{index}].rule_id is invalid")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise PolicyError(f"{context}[{index}].sha256 is invalid")
        if not isinstance(rationale, str) or not 20 <= len(rationale) <= 500:
            raise PolicyError(f"{context}[{index}].rationale is invalid")
        if not isinstance(agent_material, bool):
            raise PolicyError(f"{context}[{index}].agent_material is invalid")
        exception = ExactException(
            rule_id, _exact_path(raw.get("path"), f"{context}[{index}].path"),
            digest, rationale, agent_material
        )
        if exception in seen:
            raise PolicyError(f"{context} must contain unique exact entries")
        seen.add(exception)
        parsed.append(exception)
    return tuple(parsed)


def _protected_tag_glob_parts(pattern: str) -> tuple[str, bool]:
    if (
        not isinstance(pattern, str)
        or not pattern
        or _has_control_characters(pattern)
    ):
        raise ValueError("tag protection glob is invalid")
    if pattern == "*":
        return "", True
    wildcard = pattern.endswith("*")
    prefix = pattern[:-1] if wildcard else pattern
    if (
        not prefix
        or prefix.startswith(("/", "-"))
        or prefix.endswith(("/", "."))
        or ".." in prefix
        or "*" in prefix
        or re.fullmatch(r"[A-Za-z0-9._/-]+", prefix) is None
    ):
        raise ValueError("tag protection glob is unsupported")
    return prefix, wildcard


def _tag_regex_class_end(body: str, start: int) -> int:
    index = start + 1
    if index >= len(body) or body[index] in {"^", "]"}:
        raise ValueError("public tag regex class is unsupported")
    saw_item = False

    def class_character(position: int) -> tuple[str | None, int]:
        if position >= len(body):
            raise ValueError("public tag regex class is invalid")
        character = body[position]
        if character == "\\":
            if position + 1 >= len(body):
                raise ValueError("public tag regex class is invalid")
            escaped = body[position + 1]
            if escaped in {"d", "w"}:
                return None, position + 2
            if escaped in set(r".^$*+?{}[]\|()/-"):
                return escaped, position + 2
            raise ValueError(
                "public tag regex class escape is unsupported"
            )
        if character in {"[", "]"}:
            raise ValueError("public tag regex class is unsupported")
        return character, position + 1

    while index < len(body) and body[index] != "]":
        first, after_first = class_character(index)
        if first == "/":
            raise ValueError("public tag regex class may match slash")
        if (
            after_first < len(body)
            and body[after_first] == "-"
            and after_first + 1 < len(body)
            and body[after_first + 1] != "]"
        ):
            if first is None:
                raise ValueError(
                    "public tag regex class range is unsupported"
                )
            last, after_last = class_character(after_first + 1)
            if last is None or ord(first) > ord(last):
                raise ValueError(
                    "public tag regex class range is unsupported"
                )
            if ord(first) <= ord("/") <= ord(last):
                raise ValueError(
                    "public tag regex class may match slash"
                )
            index = after_last
        else:
            index = after_first
        saw_item = True
    if not saw_item or index >= len(body) or body[index] != "]":
        raise ValueError("public tag regex class is invalid")
    return index + 1


def _tag_regex_quantifier_end(body: str, start: int) -> int:
    if start >= len(body):
        return start
    if body[start] in {"*", "+", "?"}:
        return start + 1
    if body[start] != "{":
        return start
    match = re.match(r"\{[0-9]+(?:,[0-9]*)?\}", body[start:])
    if match is None:
        raise ValueError("public tag regex quantifier is unsupported")
    return start + match.end()


def _public_tag_regex_language(
    pattern: str,
) -> tuple[str, str | None, bool]:
    marker = "^refs/tags/"
    if (
        not isinstance(pattern, str)
        or not pattern.startswith(marker)
        or not pattern.endswith("$")
    ):
        raise ValueError("public tag regex is invalid")
    body = pattern[len(marker):-1]
    if not body:
        raise ValueError("public tag regex is invalid")
    tokens: list[tuple[str | None, bool, bool]] = []
    index = 0
    escaped_literals = set(r".^$*+?{}[]\|()/-")
    while index < len(body):
        character = body[index]
        if character == "\\":
            if index + 1 >= len(body):
                raise ValueError("public tag regex is invalid")
            escaped = body[index + 1]
            if escaped in {"d", "w"}:
                literal = None
                slash_free = True
            elif escaped in escaped_literals:
                literal = escaped
                slash_free = escaped != "/"
            else:
                raise ValueError(
                    "public tag regex escape is unsupported"
                )
            index += 2
        elif character == "[":
            literal = None
            slash_free = True
            index = _tag_regex_class_end(body, index)
        elif character in {".", "^", "$", "|", "(", ")"}:
            raise ValueError("public tag regex grammar is unsupported")
        elif character in {"*", "+", "?", "{", "}"}:
            raise ValueError("public tag regex quantifier is invalid")
        else:
            literal = character
            slash_free = character != "/"
            index += 1
        after_quantifier = _tag_regex_quantifier_end(body, index)
        quantified = after_quantifier != index
        index = after_quantifier
        if index < len(body) and body[index] in {"?", "+"} and quantified:
            raise ValueError(
                "public tag regex quantifier is unsupported"
            )
        tokens.append((literal, slash_free, quantified))

    prefix_parts: list[str] = []
    variable_index = len(tokens)
    exact_parts: list[str] = []
    exact = True
    for token_index, (literal, _, quantified) in enumerate(tokens):
        if literal is None or quantified:
            exact = False
            variable_index = min(variable_index, token_index)
            break
        prefix_parts.append(literal)
        exact_parts.append(literal)
    if exact:
        exact_literal: str | None = "".join(exact_parts)
    else:
        exact_literal = None
    variable_remainder_slash_free = all(
        slash_free
        for _, slash_free, _ in tokens[variable_index:]
    )
    return (
        "".join(prefix_parts),
        exact_literal,
        variable_remainder_slash_free,
    )


def _tag_policy_languages_covered(
    public_patterns: Sequence[str],
    protected_patterns: Sequence[str],
) -> bool:
    protected = tuple(
        _protected_tag_glob_parts(pattern)
        for pattern in protected_patterns
    )
    for pattern in public_patterns:
        (
            guaranteed_prefix,
            exact_literal,
            variable_remainder_slash_free,
        ) = _public_tag_regex_language(
            pattern
        )
        if not any(
            (
                wildcard
                and guaranteed_prefix.startswith(glob_prefix)
                and "/" not in guaranteed_prefix[len(glob_prefix):]
                and variable_remainder_slash_free
            )
            or (
                not wildcard
                and exact_literal == glob_prefix
            )
            for glob_prefix, wildcard in protected
        ):
            return False
    return True


def load_policy(path: Path) -> Policy:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PolicyError(f"policy is unreadable: {type(error).__name__}") from error
    if not isinstance(raw, dict):
        raise PolicyError("policy must be an object")
    allowed = {
        "schema_version", "repository", "public_refs", "public_identities",
        "path_exceptions", "synthetic_exceptions", "ci", "protection",
        "manual_documents", "tools"
    }
    _keys(raw, allowed, "policy")
    if set(raw) != allowed:
        raise PolicyError("policy is missing required keys")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise PolicyError("schema_version must be the integer 1")
    repository = raw["repository"]
    if not isinstance(repository, str) or not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}", repository
    ):
        raise PolicyError("repository identity is invalid")
    refs = raw["public_refs"]
    identities = raw["public_identities"]
    ci = raw["ci"]
    protection = raw["protection"]
    tools = raw["tools"]
    for value, context in (
        (refs, "public_refs"), (identities, "public_identities"), (ci, "ci"),
        (protection, "protection"), (tools, "tools")
    ):
        if not isinstance(value, dict):
            raise PolicyError(f"{context} must be an object")
    _keys(refs, {"branches", "tag_patterns"}, "public_refs")
    _keys(identities, {"email_patterns"}, "public_identities")
    _keys(ci, {"workflow", "check"}, "ci")
    _keys(protection, {
        "branches", "tag_patterns", "require_pull_request", "require_current_branch",
        "require_conversation_resolution", "deny_force_push", "deny_deletion"
    }, "protection")
    _keys(tools, {"gitleaks"}, "tools")
    branches = refs.get("branches")
    tag_patterns = refs.get("tag_patterns")
    email_patterns = identities.get("email_patterns")
    manual_documents = raw["manual_documents"]
    if not isinstance(branches, list) or not branches:
        raise PolicyError("public branches must be a non-empty unique array")
    if not all(isinstance(item, str) and re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", item) for item in branches):
        raise PolicyError("public branch is invalid")
    if len(branches) != len(set(branches)):
        raise PolicyError("public branches must be a non-empty unique array")
    if not isinstance(tag_patterns, list):
        raise PolicyError("tag patterns must be a unique array")
    if not all(isinstance(pattern, str) and len(pattern) <= 240 for pattern in tag_patterns):
        raise PolicyError("tag pattern is invalid")
    if len(tag_patterns) != len(set(tag_patterns)):
        raise PolicyError("tag patterns must be a unique array")
    if not isinstance(email_patterns, list) or not email_patterns:
        raise PolicyError("email patterns must be a non-empty array")
    if not all(isinstance(pattern, str) and 3 <= len(pattern) <= 240 for pattern in email_patterns):
        raise PolicyError("email pattern is invalid")
    if len(email_patterns) != len(set(email_patterns)):
        raise PolicyError("email patterns must be a non-empty unique array")
    for pattern in tag_patterns:
        try:
            re.compile(pattern)
        except re.error as error:
            raise PolicyError("tag pattern is invalid") from error
    for pattern in email_patterns:
        try:
            re.compile(pattern)
        except re.error as error:
            raise PolicyError("email pattern is invalid") from error
    if any(not re.fullmatch(r"\^refs/tags/.+\$", pattern) for pattern in tag_patterns):
        raise PolicyError("tag patterns must be anchored under refs/tags")
    if any(not pattern.startswith("^") or not pattern.endswith("$") for pattern in email_patterns):
        raise PolicyError("email patterns must be anchored")
    if not isinstance(manual_documents, list) or not manual_documents:
        raise PolicyError("manual_documents must be a non-empty array")
    documents = tuple(_exact_path(value, "manual document") for value in manual_documents)
    if len(documents) != len(set(documents)):
        raise PolicyError("manual_documents must be a non-empty unique array")
    if ci != {
        "workflow": ".github/workflows/public-repository-safety.yml",
        "check": "Public repository safety"
    }:
        raise PolicyError("CI must use the Public repository safety check")
    required_true = {
        "require_pull_request", "require_current_branch",
        "require_conversation_resolution", "deny_force_push", "deny_deletion"
    }
    if any(protection.get(key) is not True for key in required_true):
        raise PolicyError("all protection booleans must be true")
    protected_branches = protection.get("branches")
    protected_tags = protection.get("tag_patterns")
    if not isinstance(protected_branches, list) or not protected_branches:
        raise PolicyError("protected branches must be a non-empty array")
    if not all(isinstance(branch, str) for branch in protected_branches):
        raise PolicyError("protected branches must contain only strings")
    if len(protected_branches) != len(set(protected_branches)):
        raise PolicyError("protected branches must be a non-empty unique array")
    public_branch_names = {
        branch.removeprefix("refs/heads/") for branch in branches
    }
    if set(protected_branches) != public_branch_names:
        raise PolicyError(
            "protected branches must exactly match public branches"
        )
    if not isinstance(protected_tags, list):
        raise PolicyError("protected tag patterns must be an array")
    if not all(isinstance(pattern, str) for pattern in protected_tags):
        raise PolicyError("protected tag patterns must contain only strings")
    if len(protected_tags) != len(set(protected_tags)):
        raise PolicyError("protected tag patterns must be a unique array")
    try:
        tag_languages_covered = _tag_policy_languages_covered(
            tag_patterns, protected_tags
        )
    except ValueError:
        raise PolicyError(
            "tag protection patterns are unsupported"
        ) from None
    if not tag_languages_covered:
        raise PolicyError(
            "public tag patterns must be covered by tag protection"
        )
    if tools != {"gitleaks": "8.30.1"}:
        raise PolicyError("gitleaks version must equal 8.30.1")
    return Policy(
        1, repository, tuple(branches), tuple(tag_patterns), tuple(email_patterns),
        _exceptions(raw["path_exceptions"], "path_exceptions"),
        _exceptions(raw["synthetic_exceptions"], "synthetic_exceptions"),
        ci["workflow"], ci["check"], tuple(protected_branches),
        tuple(protected_tags), documents, tools["gitleaks"]
    )


class AuditInputError(RuntimeError):
    pass


@dataclass(frozen=True)
class GitObject:
    mode: str
    object_id: str
    path: str
    commit: str


@dataclass(frozen=True)
class RepositorySnapshot:
    root: Path
    git_dir: Path
    common_dir: Path
    refs: tuple[tuple[str, str], ...]
    public_branches: tuple[str, ...]
    public_tag_patterns: tuple[str, ...]
    commits: tuple[str, ...]
    objects: tuple[GitObject, ...]
    git_config: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class GitHubState:
    visibility: str
    default_branch: str
    complete: bool
    findings: tuple[Finding, ...]
    candidate_bound: bool = False


@dataclass(frozen=True)
class _GitHubControls:
    visibility: str
    default_branch: str
    enabled_surfaces: tuple[bool, bool, bool]
    secret_scanning: str
    push_protection: str
    branches: tuple[tuple[str, str], ...]
    tags: tuple[tuple[str, str], ...]
    branch_protected: bool
    tags_protected: bool
    vulnerability_reporting: bool
    actions_permission: str
    actions_can_approve: bool
    producer_app_id: int | None
    digest: str


@dataclass(frozen=True)
class _GitHubCallEvidence:
    argv: tuple[str, ...]
    returncode: int
    stdout_length: int
    stdout_sha256: str


GITHUB_REPOSITORY_PATTERN = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}"
)
GITHUB_SHA_PATTERN = re.compile(r"[0-9a-f]{40,64}")
GITHUB_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
GITHUB_MAX_PAGES = 100
GITHUB_MAX_ITEMS = 10_000
GITHUB_MAX_REFS = 100
GITHUB_MAX_NESTED_SURFACES = 100
GITHUB_MAX_INSPECTION_CALLS = 256
GITHUB_PAGE_RESPONSE_LIMIT = 1024 * 1024
GITHUB_MAX_STDERR_BYTES = 64 * 1024
GITHUB_COMMAND_TIMEOUT_SECONDS = 30.0
GITHUB_PROCESS_TERMINATION_SECONDS = 1.0
GITHUB_PROCESS_READ_CHUNK_BYTES = 64 * 1024
_WINDOWS_CREATE_SUSPENDED = 0x00000004
_WINDOWS_CREATE_NO_WINDOW = 0x08000000
_WINDOWS_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_WINDOWS_JOB_KILL_ON_CLOSE = 0x00002000
_WINDOWS_TOOLHELP_SNAPSHOT_THREADS = 0x00000004
_WINDOWS_THREAD_SUSPEND_RESUME = 0x0002
_WINDOWS_INVALID_DWORD = 0xFFFFFFFF
ACTION_LOG_ARCHIVE_LIMIT = 25 * 1024 * 1024
ACTION_LOG_TOTAL_LIMIT = 25 * 1024 * 1024
ACTION_LOG_ENTRY_LIMIT = 5 * 1024 * 1024
ACTION_LOG_ENTRY_COUNT_LIMIT = 2_000
ACTION_LOG_COMPRESSION_RATIO_LIMIT = 200
ACTION_LOG_READ_CHUNK_BYTES = 64 * 1024
ACTION_LOG_SCAN_OVERLAP_BYTES = 512
ACTION_LOG_MARKERS = (
    re.compile(
        rb"(?i)(?:password|secret|api[_-]?key|private[_-]?key)"
        rb"\s*[:=]\s*[^\s]{4,}"
    ),
    re.compile(
        rb"-----BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY-----"
    ),
)
GITHUB_EMPTY_SURFACES = (
    (
        "/issues?state=all&per_page=100",
        "github.issue",
        "number",
    ),
    (
        "/issues/comments?per_page=100",
        "github.issue-comment",
        "id",
    ),
    (
        "/pulls/comments?per_page=100",
        "github.review-comment",
        "id",
    ),
    (
        "/releases?per_page=100",
        "github.release",
        "id",
    ),
    (
        "/deployments?per_page=100",
        "github.deployment",
        "id",
    ),
    (
        "/forks?per_page=100",
        "github.fork",
        "id",
    ),
    (
        "/secret-scanning/alerts?state=open&per_page=100",
        "github.secret-alert",
        "number",
    ),
    (
        "/secret-scanning/alerts?state=resolved&per_page=100",
        "github.secret-alert",
        "number",
    ),
    (
        "/code-scanning/alerts?state=open&per_page=100",
        "github.code-alert",
        "number",
    ),
    (
        "/code-scanning/alerts?state=dismissed&per_page=100",
        "github.code-alert",
        "number",
    ),
    (
        "/code-scanning/alerts?state=fixed&per_page=100",
        "github.code-alert",
        "number",
    ),
)
PACKAGE_QUERY = (
    "query($owner:String!,$name:String!){"
    "repository(owner:$owner,name:$name){packages(first:100){"
    "nodes{name packageType}pageInfo{hasNextPage endCursor}}}}"
)


def github_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "GH_HOST": "github.com",
        "GH_PROMPT_DISABLED": "1",
        "GH_PAGER": "cat",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "PAGER": "cat",
        "NO_COLOR": "1",
        "LC_ALL": "C",
    }
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(name)
        if value and not _has_control_characters(value):
            environment[name] = value
    return environment


class _WindowsJobBasicLimitInformation(ctypes.Structure):
    _fields_ = (
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", ctypes.wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.wintypes.DWORD),
        ("SchedulingClass", ctypes.wintypes.DWORD),
    )


class _WindowsIoCounters(ctypes.Structure):
    _fields_ = tuple(
        (name, ctypes.c_ulonglong)
        for name in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        )
    )


class _WindowsJobExtendedLimitInformation(ctypes.Structure):
    _fields_ = (
        ("BasicLimitInformation", _WindowsJobBasicLimitInformation),
        ("IoInfo", _WindowsIoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    )


class _WindowsThreadEntry(ctypes.Structure):
    _fields_ = (
        ("dwSize", ctypes.wintypes.DWORD),
        ("cntUsage", ctypes.wintypes.DWORD),
        ("th32ThreadID", ctypes.wintypes.DWORD),
        ("th32OwnerProcessID", ctypes.wintypes.DWORD),
        ("tpBasePri", ctypes.wintypes.LONG),
        ("tpDeltaPri", ctypes.wintypes.LONG),
        ("dwFlags", ctypes.wintypes.DWORD),
    )


class _DarwinSigval(ctypes.Union):
    _fields_ = (
        ("sival_int", ctypes.c_int),
        ("sival_ptr", ctypes.c_void_p),
    )


class _DarwinSiginfo(ctypes.Structure):
    _fields_ = (
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("si_pid", ctypes.c_int),
        ("si_uid", ctypes.c_uint),
        ("si_status", ctypes.c_int),
        ("si_addr", ctypes.c_void_p),
        ("si_value", _DarwinSigval),
        ("si_band", ctypes.c_long),
        ("_pad", ctypes.c_ulong * 7),
    )


def _windows_function(
    function,
    argument_types: Sequence[object],
    result_type: object,
) -> None:
    try:
        function.argtypes = list(argument_types)
        function.restype = result_type
    except AttributeError:
        pass


def _configure_windows_kernel(kernel) -> None:
    handle = ctypes.wintypes.HANDLE
    pointer = ctypes.c_void_p
    dword = ctypes.wintypes.DWORD
    boolean = ctypes.wintypes.BOOL
    _windows_function(
        kernel.CreateJobObjectW,
        (pointer, ctypes.wintypes.LPCWSTR),
        handle,
    )
    _windows_function(
        kernel.SetInformationJobObject,
        (handle, ctypes.c_int, pointer, dword),
        boolean,
    )
    _windows_function(
        kernel.AssignProcessToJobObject,
        (handle, handle),
        boolean,
    )
    _windows_function(
        kernel.TerminateJobObject,
        (handle, ctypes.wintypes.UINT),
        boolean,
    )
    _windows_function(kernel.CloseHandle, (handle,), boolean)
    _windows_function(
        kernel.CreateToolhelp32Snapshot,
        (dword, dword),
        handle,
    )
    _windows_function(
        kernel.Thread32First,
        (handle, ctypes.POINTER(_WindowsThreadEntry)),
        boolean,
    )
    _windows_function(
        kernel.Thread32Next,
        (handle, ctypes.POINTER(_WindowsThreadEntry)),
        boolean,
    )
    _windows_function(
        kernel.OpenThread,
        (dword, boolean, dword),
        handle,
    )
    _windows_function(
        kernel.ResumeThread,
        (handle,),
        dword,
    )


def _invalid_windows_handle(value: object) -> bool:
    return value in {
        None,
        0,
        ctypes.c_void_p(-1).value,
    }


class _WindowsJob:
    def __init__(self, kernel, handle: object) -> None:
        self.kernel = kernel
        self.handle = handle
        self.limit_flags = _WINDOWS_JOB_KILL_ON_CLOSE
        self.closed = False

    @classmethod
    def create(cls, kernel=None) -> _WindowsJob:
        if kernel is None:
            if os.name != "nt" or not hasattr(ctypes, "WinDLL"):
                raise AuditInputError(
                    "Windows process containment is unavailable"
                )
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        try:
            _configure_windows_kernel(kernel)
        except AttributeError:
            raise AuditInputError(
                "Windows process containment is unavailable"
            ) from None
        handle = kernel.CreateJobObjectW(None, None)
        if _invalid_windows_handle(handle):
            raise AuditInputError("Windows job creation failed")
        information = _WindowsJobExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = (
            _WINDOWS_JOB_KILL_ON_CLOSE
        )
        try:
            configured = kernel.SetInformationJobObject(
                handle,
                _WINDOWS_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(information),
                ctypes.sizeof(information),
            )
        except (OSError, TypeError, ValueError):
            try:
                kernel.CloseHandle(handle)
            except (OSError, TypeError, ValueError):
                pass
            raise AuditInputError(
                "Windows job configuration failed"
            ) from None
        if not configured:
            kernel.CloseHandle(handle)
            raise AuditInputError("Windows job configuration failed")
        return cls(kernel, handle)

    def _close_handle(self, handle: object) -> None:
        if not self.kernel.CloseHandle(handle):
            raise AuditInputError("Windows handle cleanup failed")

    def terminate(self, force: bool = True) -> None:
        if (
            not self.closed
            and not self.kernel.TerminateJobObject(self.handle, 124)
        ):
            raise AuditInputError("Windows job termination failed")

    def assign_and_resume(self, process) -> None:
        process_handle = getattr(process, "_handle", None)
        process_id = getattr(process, "pid", None)
        try:
            if (
                _invalid_windows_handle(process_handle)
                or type(process_id) is not int
                or process_id <= 0
                or not self.kernel.AssignProcessToJobObject(
                    self.handle, process_handle
                )
            ):
                raise AuditInputError("Windows job assignment failed")
            snapshot = self.kernel.CreateToolhelp32Snapshot(
                _WINDOWS_TOOLHELP_SNAPSHOT_THREADS, 0
            )
            if _invalid_windows_handle(snapshot):
                raise AuditInputError(
                    "Windows suspended thread lookup failed"
                )
            thread_handle = None
            try:
                entry = _WindowsThreadEntry()
                entry.dwSize = ctypes.sizeof(entry)
                found = self.kernel.Thread32First(
                    snapshot, ctypes.byref(entry)
                )
                while found:
                    if entry.th32OwnerProcessID == process_id:
                        thread_handle = self.kernel.OpenThread(
                            _WINDOWS_THREAD_SUSPEND_RESUME,
                            False,
                            entry.th32ThreadID,
                        )
                        if _invalid_windows_handle(thread_handle):
                            raise AuditInputError(
                                "Windows suspended thread open failed"
                            )
                        break
                    found = self.kernel.Thread32Next(
                        snapshot, ctypes.byref(entry)
                    )
                if thread_handle is None:
                    raise AuditInputError(
                        "Windows suspended thread was not found"
                    )
                try:
                    previous_count = self.kernel.ResumeThread(
                        thread_handle
                    )
                    if previous_count != 1:
                        raise AuditInputError(
                            "Windows suspended thread resume failed"
                        )
                finally:
                    self._close_handle(thread_handle)
            finally:
                self._close_handle(snapshot)
        except (AuditInputError, OSError, TypeError, ValueError):
            try:
                self.terminate()
            except AuditInputError:
                pass
            raise AuditInputError(
                "Windows suspended process containment failed"
            ) from None

    def close(self) -> None:
        if self.closed:
            return
        if not self.kernel.CloseHandle(self.handle):
            raise AuditInputError("Windows job cleanup failed")
        self.closed = True


class _PosixProcessGroup:
    def __init__(self, process_group: int) -> None:
        self.process_group = process_group

    @classmethod
    def create(cls, process) -> _PosixProcessGroup:
        process_id = getattr(process, "pid", None)
        if (
            type(process_id) is not int
            or process_id <= 1
            or process_id in {os.getpgrp(), os.getsid(0)}
        ):
            raise AuditInputError("POSIX process group is invalid")
        try:
            process_group = os.getpgid(process_id)
            session = os.getsid(process_id)
        except ProcessLookupError:
            if not _posix_child_completed_unreaped(process_id):
                raise AuditInputError(
                    "POSIX process identity was lost"
                ) from None
            return cls(process_id)
        if process_group != process_id or session != process_id:
            raise AuditInputError("POSIX process group is invalid")
        return cls(process_id)

    def terminate(self, force: bool = True) -> None:
        _posix_child_completed_unreaped(self.process_group)
        try:
            os.killpg(
                self.process_group,
                signal.SIGKILL if force else signal.SIGTERM,
            )
        except ProcessLookupError:
            pass
        except PermissionError:
            if not _posix_child_completed_unreaped(
                self.process_group
            ):
                raise AuditInputError(
                    "POSIX process group termination failed"
                ) from None
        except (OSError, ValueError):
            raise AuditInputError(
                "POSIX process group termination failed"
            ) from None

    def close(self) -> None:
        return None


def _posix_waitid_options() -> int:
    constants = (
        getattr(os, "P_PID", None),
        getattr(os, "WEXITED", None),
        getattr(os, "WNOHANG", None),
        getattr(os, "WNOWAIT", None),
    )
    if not all(type(value) is int for value in constants):
        raise AuditInputError("POSIX wait identity is unavailable")
    return os.WEXITED | os.WNOHANG | os.WNOWAIT


def _completed_wait_identity(
    process_id: int,
    signal_number: object,
    reported_process_id: object,
    code: object,
    error_number: object,
) -> bool:
    values = (
        signal_number,
        reported_process_id,
        code,
        error_number,
    )
    if not all(type(value) is int for value in values):
        raise AuditInputError("POSIX wait identity is ambiguous")
    if reported_process_id == 0:
        if any(values):
            raise AuditInputError("POSIX wait identity is ambiguous")
        return False
    if (
        signal_number != signal.SIGCHLD
        or reported_process_id != process_id
        or code not in {1, 2, 3}
        or error_number != 0
    ):
        raise AuditInputError("POSIX wait identity is ambiguous")
    return True


def _darwin_siginfo_layout_valid() -> bool:
    expected_offsets = {
        "si_signo": 0,
        "si_errno": 4,
        "si_code": 8,
        "si_pid": 12,
        "si_uid": 16,
        "si_status": 20,
        "si_addr": 24,
        "si_value": 32,
        "si_band": 40,
        "_pad": 48,
    }
    return (
        ctypes.sizeof(_DarwinSiginfo) == 104
        and all(
            getattr(_DarwinSiginfo, name).offset == offset
            for name, offset in expected_offsets.items()
        )
    )


def _darwin_child_completed_unreaped(
    process_id: int,
    libc=None,
) -> bool:
    if (
        sys.platform != "darwin"
        or type(process_id) is not int
        or process_id <= 0
        or not _darwin_siginfo_layout_valid()
        or os.P_PID != 1
        or os.WEXITED != 0x04
        or os.WNOHANG != 0x01
        or os.WNOWAIT != 0x20
    ):
        raise AuditInputError("Darwin wait identity is unavailable")
    if libc is None:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
        except OSError:
            raise AuditInputError(
                "Darwin wait identity is unavailable"
            ) from None
    try:
        waitid = libc.waitid
    except AttributeError:
        raise AuditInputError(
            "Darwin wait identity is unavailable"
        ) from None
    try:
        waitid.argtypes = (
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.POINTER(_DarwinSiginfo),
            ctypes.c_int,
        )
        waitid.restype = ctypes.c_int
    except AttributeError:
        pass
    information = _DarwinSiginfo()
    ctypes.set_errno(0)
    try:
        result = waitid(
            os.P_PID,
            process_id,
            ctypes.byref(information),
            _posix_waitid_options(),
        )
    except (OSError, TypeError, ValueError):
        raise AuditInputError(
            "Darwin wait identity failed"
        ) from None
    error_number = ctypes.get_errno()
    if result != 0 or error_number != 0:
        raise AuditInputError("Darwin wait identity failed")
    if information.si_pid == 0:
        if any(
            ctypes.string_at(
                ctypes.byref(information),
                ctypes.sizeof(information),
            )
        ):
            raise AuditInputError(
                "Darwin wait identity is ambiguous"
            )
        return False
    return _completed_wait_identity(
        process_id,
        information.si_signo,
        information.si_pid,
        information.si_code,
        information.si_errno,
    )


def _posix_child_completed_unreaped(process_id: int) -> bool:
    if type(process_id) is not int or process_id <= 0:
        raise AuditInputError("POSIX wait identity is invalid")
    waitid = getattr(os, "waitid", None)
    if waitid is None:
        if sys.platform == "darwin":
            return _darwin_child_completed_unreaped(process_id)
        raise AuditInputError("POSIX wait identity is unavailable")
    try:
        result = waitid(
            os.P_PID,
            process_id,
            _posix_waitid_options(),
        )
    except (ChildProcessError, OSError, TypeError, ValueError):
        raise AuditInputError("POSIX wait identity failed") from None
    if result is None:
        return False
    return _completed_wait_identity(
        process_id,
        getattr(result, "si_signo", None),
        getattr(result, "si_pid", None),
        getattr(result, "si_code", None),
        0,
    )


def _bounded_process_wait(process, deadline: float) -> bool:
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            process.wait(timeout=min(0.05, remaining))
        except subprocess.TimeoutExpired:
            continue
        except OSError:
            return False
        return True
    return process.poll() is not None


def _close_unread_process_streams(process) -> None:
    for stream in (
        getattr(process, "stdout", None),
        getattr(process, "stderr", None),
    ):
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                pass


def run_github_command(
    argv: Sequence[str],
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    windows_job: _WindowsJob | None = None
    popen_options: dict[str, object] = {}
    try:
        if os.name == "nt":
            windows_job = _WindowsJob.create()
            popen_options["creationflags"] = (
                _WINDOWS_CREATE_SUSPENDED
                | _WINDOWS_CREATE_NO_WINDOW
            )
        elif os.name == "posix":
            # WNOWAIT retains identity only while this private child has no
            # inherited SIGCHLD handler that could reap it independently.
            if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
                raise AuditInputError(
                    "inherited SIGCHLD handling is unsupported"
                )
            popen_options["start_new_session"] = True
        else:
            return CommandResult(127, b"", b"")
        process = subprocess.Popen(
            list(argv),
            cwd=os.fspath(cwd) if cwd else None,
            env=dict(env) if env is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **popen_options,
        )
    except (AuditInputError, OSError, TypeError, ValueError):
        if windows_job is not None:
            try:
                windows_job.close()
            except AuditInputError:
                pass
        return CommandResult(127, b"", b"")

    try:
        if windows_job is not None:
            windows_job.assign_and_resume(process)
            process_tree: _WindowsJob | _PosixProcessGroup = (
                windows_job
            )
        else:
            process_tree = _PosixProcessGroup.create(process)
    except AuditInputError:
        if windows_job is not None:
            try:
                windows_job.terminate()
            except AuditInputError:
                pass
            try:
                process.kill()
            except OSError:
                pass
        _bounded_process_wait(
            process,
            time.monotonic() + GITHUB_PROCESS_TERMINATION_SECONDS,
        )
        _close_unread_process_streams(process)
        if windows_job is not None:
            try:
                windows_job.close()
            except AuditInputError:
                pass
        return CommandResult(127, b"", b"")

    if process.stdout is None or process.stderr is None:
        try:
            process_tree.terminate()
        except AuditInputError:
            pass
        if windows_job is not None:
            try:
                process.kill()
            except OSError:
                pass
        _bounded_process_wait(
            process,
            time.monotonic() + GITHUB_PROCESS_TERMINATION_SECONDS,
        )
        _close_unread_process_streams(process)
        try:
            process_tree.close()
        except AuditInputError:
            pass
        return CommandResult(127, b"", b"")

    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    reader_failed = threading.Event()
    stop_readers = threading.Event()
    posix_reader = isinstance(process_tree, _PosixProcessGroup)

    def drain_buffered(
        stream, target: bytearray, limit: int
    ) -> None:
        try:
            while True:
                chunk = stream.read(GITHUB_PROCESS_READ_CHUNK_BYTES)
                if not chunk:
                    break
                if len(target) + len(chunk) > limit:
                    overflow.set()
                    return
                target.extend(chunk)
        except (OSError, ValueError):
            reader_failed.set()
        finally:
            stream.close()

    def drain_posix(stream, target: bytearray, limit: int) -> None:
        try:
            descriptor = stream.fileno()
        except (AttributeError, OSError, ValueError):
            reader_failed.set()
            return
        if type(descriptor) is not int or descriptor < 0:
            reader_failed.set()
            return
        while not stop_readers.is_set():
            try:
                readable, _, _ = select.select(
                    (descriptor,), (), (), 0.05
                )
            except InterruptedError:
                continue
            except (OSError, TypeError, ValueError):
                reader_failed.set()
                return
            if not readable:
                continue
            try:
                chunk = os.read(
                    descriptor, GITHUB_PROCESS_READ_CHUNK_BYTES
                )
            except (BlockingIOError, InterruptedError):
                continue
            except (OSError, ValueError):
                reader_failed.set()
                return
            if not chunk:
                return
            if len(target) + len(chunk) > limit:
                overflow.set()
                return
            target.extend(chunk)

    drain = drain_posix if posix_reader else drain_buffered
    readers = (
        threading.Thread(
            target=drain,
            args=(process.stdout, stdout, ACTION_LOG_ARCHIVE_LIMIT),
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=(process.stderr, stderr, GITHUB_MAX_STDERR_BYTES),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + GITHUB_COMMAND_TIMEOUT_SECONDS
    timed_out = False
    observation_failed = False
    command_returncode: int | None = None
    if isinstance(process_tree, _PosixProcessGroup):
        while True:
            if overflow.is_set() or reader_failed.is_set():
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                if _posix_child_completed_unreaped(process.pid):
                    break
            except AuditInputError:
                # A foreign waitpid cannot be excluded. Once WNOWAIT proof
                # is lost, this invocation permanently enters no-signal
                # cleanup rather than trusting the stored numeric PGID.
                observation_failed = True
                break
            time.sleep(min(0.01, remaining))
    else:
        while process.poll() is None:
            if overflow.is_set() or reader_failed.is_set():
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                command_returncode = process.wait(
                    timeout=min(0.05, remaining)
                )
                break
            except subprocess.TimeoutExpired:
                continue
            except OSError:
                timed_out = True
                break
        if (
            command_returncode is None
            and process.returncode is not None
        ):
            command_returncode = process.returncode

    termination_deadline = (
        time.monotonic() + GITHUB_PROCESS_TERMINATION_SECONDS
    )
    cleanup_failed = False
    posix_identity_lost = bool(
        observation_failed
        and isinstance(process_tree, _PosixProcessGroup)
    )
    if posix_identity_lost:
        stop_readers.set()
    if (
        timed_out
        or overflow.is_set()
        or reader_failed.is_set()
        or observation_failed
    ):
        if not posix_identity_lost:
            try:
                process_tree.terminate(force=False)
            except AuditInputError:
                cleanup_failed = True
                if isinstance(
                    process_tree, _PosixProcessGroup
                ):
                    posix_identity_lost = True
                    stop_readers.set()
        if isinstance(process_tree, _PosixProcessGroup):
            time.sleep(
                max(
                    0.0,
                    min(
                        0.05,
                        termination_deadline - time.monotonic(),
                    ),
                )
            )
        else:
            _bounded_process_wait(
                process,
                min(
                    termination_deadline,
                    time.monotonic() + 0.05,
                ),
            )
    if not posix_identity_lost:
        try:
            process_tree.terminate(force=True)
        except AuditInputError:
            cleanup_failed = True
            if isinstance(process_tree, _PosixProcessGroup):
                posix_identity_lost = True
                stop_readers.set()
    try:
        process_tree.close()
    except AuditInputError:
        cleanup_failed = True
    if posix_identity_lost:
        for reader in readers:
            reader.join(
                timeout=max(
                    0.0,
                    termination_deadline - time.monotonic(),
                )
            )
        if not any(reader.is_alive() for reader in readers):
            _close_unread_process_streams(process)
    reaped = _bounded_process_wait(process, termination_deadline)
    if (
        isinstance(process_tree, _PosixProcessGroup)
        and reaped
        and type(process.returncode) is int
    ):
        command_returncode = process.returncode
    for reader in readers:
        reader.join(
            timeout=max(
                0.0, termination_deadline - time.monotonic()
            )
        )
    readers_alive = any(reader.is_alive() for reader in readers)
    if not readers_alive:
        _close_unread_process_streams(process)
    if (
        timed_out
        or overflow.is_set()
        or reader_failed.is_set()
        or observation_failed
        or cleanup_failed
        or not reaped
        or readers_alive
        or command_returncode is None
    ):
        return CommandResult(124, b"", b"")
    return CommandResult(
        command_returncode,
        bytes(stdout),
        bytes(stderr),
    )


class _InspectionRunner:
    def __init__(self, runner: Runner) -> None:
        self.runner = runner
        self.environment = github_environment()
        self.calls = 0

    def __call__(self, argv, cwd, env):
        self.calls += 1
        if self.calls > GITHUB_MAX_INSPECTION_CALLS:
            raise AuditInputError(
                "GitHub inspection call budget was exceeded"
            )
        return self.runner(argv, cwd, self.environment)


class _TranscriptRunner:
    def __init__(self, runner: Runner) -> None:
        self.runner = runner
        self.evidence: list[_GitHubCallEvidence] = []

    def __call__(self, argv, cwd, env):
        result = self.runner(argv, cwd, env)
        if (
            isinstance(result, CommandResult)
            and type(result.returncode) is int
            and isinstance(result.stdout, bytes)
            and len(result.stdout) <= ACTION_LOG_ARCHIVE_LIMIT
        ):
            self.evidence.append(
                _GitHubCallEvidence(
                    tuple(argv),
                    result.returncode,
                    len(result.stdout),
                    hash_bytes(result.stdout),
                )
            )
        return result


def github_repository_from_remote(remote: str) -> str:
    if (
        not isinstance(remote, str)
        or not remote
        or _has_control_characters(remote)
        or "%" in remote
    ):
        raise AuditInputError("GitHub remote is invalid")
    scp = re.fullmatch(
        r"git@github\.com:"
        r"([a-z0-9](?:[a-z0-9-]{0,38})/"
        r"[A-Za-z0-9._-]{1,100})\.git",
        remote,
    )
    if scp is not None:
        return scp.group(1)
    try:
        parsed = urllib.parse.urlsplit(remote)
        port = parsed.port
    except ValueError:
        raise AuditInputError("GitHub remote is invalid") from None
    if (
        parsed.query
        or parsed.fragment
        or port is not None
        or parsed.hostname != "github.com"
        or parsed.path.count("/") != 2
        or not parsed.path.endswith(".git")
    ):
        raise AuditInputError("GitHub remote is invalid")
    if parsed.scheme == "https":
        if (
            parsed.netloc != "github.com"
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise AuditInputError("GitHub remote is invalid")
    elif parsed.scheme == "ssh":
        if (
            parsed.netloc != "git@github.com"
            or parsed.username != "git"
            or parsed.password is not None
        ):
            raise AuditInputError("GitHub remote is invalid")
    else:
        raise AuditInputError("GitHub remote is invalid")
    repository = parsed.path.removeprefix("/").removesuffix(".git")
    if GITHUB_REPOSITORY_PATTERN.fullmatch(repository) is None:
        raise AuditInputError("GitHub remote is invalid")
    return repository


def _github_repository_path(repository: str) -> str:
    if (
        not isinstance(repository, str)
        or GITHUB_REPOSITORY_PATTERN.fullmatch(repository) is None
    ):
        raise AuditInputError("GitHub repository identity is invalid")
    owner, name = repository.split("/", 1)
    return (
        "repos/"
        + urllib.parse.quote(owner, safe="")
        + "/"
        + urllib.parse.quote(name, safe="")
    )


def _github_authenticated(runner: Runner) -> None:
    payload = _github_json_payload(
        _github_result(("gh", "api", "user"), runner)
    )
    if (
        not isinstance(payload, dict)
        or not _positive_integer(payload.get("id"))
        or not isinstance(payload.get("login"), str)
        or not payload["login"]
        or len(payload["login"]) > 100
        or _has_control_characters(payload["login"])
    ):
        raise AuditInputError("GitHub authentication is unavailable")


def _github_result(
    arguments: Sequence[str],
    runner: Runner,
    *,
    limit: int = GITHUB_MAX_RESPONSE_BYTES,
) -> bytes:
    if (
        not arguments
        or arguments[0] != "gh"
        or tuple(arguments[:2]) != ("gh", "api")
        or any(
            not isinstance(item, str)
            or not item
            or _has_control_characters(item)
            for item in arguments
        )
    ):
        raise AuditInputError("GitHub inspection command is invalid")
    try:
        result = runner(tuple(arguments), None, github_environment())
    except OSError:
        raise AuditInputError("GitHub surface inspection failed") from None
    if (
        not isinstance(result, CommandResult)
        or type(result.returncode) is not int
        or result.returncode != 0
        or not isinstance(result.stdout, bytes)
        or not isinstance(result.stderr, bytes)
        or result.stderr
        or len(result.stdout) == 0
        or len(result.stdout) > limit
    ):
        raise AuditInputError("GitHub surface inspection failed")
    return result.stdout


def _github_json_payload(payload: bytes) -> object:
    try:
        return json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_object_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("invalid JSON constant")
            ),
        )
    except (
        UnicodeError,
        json.JSONDecodeError,
        PolicyError,
        TypeError,
        ValueError,
        RecursionError,
    ):
        raise AuditInputError("GitHub surface response is invalid") from None


def _gh_json(
    repository: str,
    endpoint: str,
    runner: Runner,
) -> object:
    base = _github_repository_path(repository)
    return _github_json_payload(
        _github_result(("gh", "api", base + endpoint), runner)
    )


def _gh_list(
    repository: str,
    endpoint: str,
    runner: Runner,
    *,
    field: str | None = None,
    total_field: str | None = None,
) -> list[object]:
    base = _github_repository_path(repository)
    if (
        re.search(r"(?:\?|&)per_page=100(?:&|$)", endpoint) is None
        or re.search(r"(?:\?|&)page=", endpoint) is not None
    ):
        raise AuditInputError("GitHub paginated endpoint is invalid")
    values: list[object] = []
    page_digests: set[str] = set()
    item_digests: set[str] = set()
    expected_total: int | None = None
    for page_number in range(1, GITHUB_MAX_PAGES + 1):
        payload = _github_result(
            (
                "gh",
                "api",
                base + endpoint + f"&page={page_number}",
            ),
            runner,
            limit=GITHUB_PAGE_RESPONSE_LIMIT,
        )
        page = _github_json_payload(payload)
        try:
            page_digest = hash_bytes(canonical_json(page))
        except (TypeError, ValueError, RecursionError):
            raise AuditInputError(
                "GitHub paginated response is invalid"
            ) from None
        if page_digest in page_digests:
            raise AuditInputError(
                "GitHub paginated response is duplicated"
            )
        page_digests.add(page_digest)
        if field is None:
            page_values = page
        else:
            if not isinstance(page, dict):
                raise AuditInputError(
                    "GitHub paginated response is invalid"
                )
            page_values = page.get(field)
            if total_field is not None:
                total = page.get(total_field)
                if type(total) is not int or total < 0:
                    raise AuditInputError(
                        "GitHub paginated total is invalid"
                    )
                if expected_total is None:
                    expected_total = total
                elif total != expected_total:
                    raise AuditInputError(
                        "GitHub paginated total changed"
                    )
                if expected_total > GITHUB_MAX_ITEMS:
                    raise AuditInputError(
                        "GitHub paginated total exceeded its bound"
                    )
        if not isinstance(page_values, list) or len(page_values) > 100:
            raise AuditInputError("GitHub paginated page is invalid")
        for item in page_values:
            try:
                item_digest = hash_bytes(canonical_json(item))
            except (TypeError, ValueError, RecursionError):
                raise AuditInputError(
                    "GitHub paginated item is invalid"
                ) from None
            if item_digest in item_digests:
                raise AuditInputError(
                    "GitHub paginated item is duplicated"
                )
            item_digests.add(item_digest)
            values.append(item)
            if len(values) > GITHUB_MAX_ITEMS:
                raise AuditInputError(
                    "GitHub paginated response exceeded its bound"
                )
        if expected_total is not None:
            if len(values) > expected_total:
                raise AuditInputError(
                    "GitHub paginated response exceeded its total"
                )
            if len(values) == expected_total:
                break
            if len(page_values) < 100:
                raise AuditInputError(
                    "GitHub paginated response was truncated"
                )
        elif len(page_values) < 100:
            break
        if page_number == GITHUB_MAX_PAGES:
            raise AuditInputError(
                "GitHub pagination exceeded its page bound"
            )
    if expected_total is not None and expected_total != len(values):
        raise AuditInputError("GitHub paginated response was truncated")
    return values


def _github_finding(rule_id: str, classification: str) -> Finding:
    return Finding(
        rule_id,
        classification,
        "",
        "github",
        "GitHub publication control or retained surface requires review",
    )


def _add_github_finding(
    findings: dict[str, Finding],
    rule_id: str,
    classification: str = "github-control",
) -> None:
    findings.setdefault(
        rule_id, _github_finding(rule_id, classification)
    )


def _valid_github_sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and GITHUB_SHA_PATTERN.fullmatch(value) is not None
    )


def _positive_integer(value: object) -> bool:
    return type(value) is int and value > 0


def _identity_items(
    values: object,
    identity: str,
) -> list[dict[str, object]]:
    if not isinstance(values, list):
        raise AuditInputError("GitHub surface response is invalid")
    result: list[dict[str, object]] = []
    seen: set[int] = set()
    for value in values:
        if (
            not isinstance(value, dict)
            or not _positive_integer(value.get(identity))
            or value[identity] in seen
        ):
            raise AuditInputError("GitHub surface identity is invalid")
        seen.add(value[identity])
        result.append(value)
    return result


def _github_branches(values: object) -> dict[str, str]:
    if not isinstance(values, list):
        raise AuditInputError("GitHub branch response is invalid")
    branches: dict[str, str] = {}
    for value in values:
        commit = value.get("commit") if isinstance(value, dict) else None
        name = value.get("name") if isinstance(value, dict) else None
        sha = commit.get("sha") if isinstance(commit, dict) else None
        if (
            not isinstance(name, str)
            or not name
            or name.startswith(("/", "-"))
            or name.endswith(("/", "."))
            or ".." in name
            or _has_control_characters(name)
            or not _valid_github_sha(sha)
            or name in branches
        ):
            raise AuditInputError("GitHub branch response is invalid")
        branches[name] = sha
    return branches


def _github_tags(values: object) -> dict[str, str]:
    if not isinstance(values, list):
        raise AuditInputError("GitHub tag response is invalid")
    tags: dict[str, str] = {}
    for value in values:
        commit = value.get("commit") if isinstance(value, dict) else None
        name = value.get("name") if isinstance(value, dict) else None
        sha = commit.get("sha") if isinstance(commit, dict) else None
        if (
            not isinstance(name, str)
            or not name
            or name.startswith(("/", "-"))
            or name.endswith(("/", "."))
            or ".." in name
            or _has_control_characters(name)
            or not _valid_github_sha(sha)
            or name in tags
        ):
            raise AuditInputError("GitHub tag response is invalid")
        tags[name] = sha
    return tags


def branch_protection_satisfies(value: object, policy: Policy) -> bool:
    if not isinstance(value, dict):
        return False
    checks = value.get("required_status_checks")
    reviews = value.get("required_pull_request_reviews")
    contexts = checks.get("contexts") if isinstance(checks, dict) else None
    review_count = (
        reviews.get("required_approving_review_count")
        if isinstance(reviews, dict)
        else None
    )
    return (
        isinstance(checks, dict)
        and checks.get("strict") is True
        and isinstance(contexts, list)
        and all(isinstance(item, str) for item in contexts)
        and policy.ci_check in contexts
        and isinstance(reviews, dict)
        and type(review_count) is int
        and review_count >= 1
        and isinstance(value.get("enforce_admins"), dict)
        and value["enforce_admins"].get("enabled") is True
        and isinstance(
            value.get("required_conversation_resolution"), dict
        )
        and value["required_conversation_resolution"].get("enabled") is True
        and isinstance(value.get("allow_force_pushes"), dict)
        and value["allow_force_pushes"].get("enabled") is False
        and isinstance(value.get("allow_deletions"), dict)
        and value["allow_deletions"].get("enabled") is False
    )


def _branch_protection_producer(
    value: object,
    policy: Policy,
) -> int | None:
    checks = (
        value.get("required_status_checks")
        if isinstance(value, dict)
        else None
    )
    producers = (
        checks.get("checks")
        if isinstance(checks, dict)
        else None
    )
    if producers is None:
        return None
    if not isinstance(producers, list):
        raise AuditInputError(
            "GitHub branch protection producer is invalid"
        )
    matches: list[int] = []
    for producer in producers:
        if (
            not isinstance(producer, dict)
            or not isinstance(producer.get("context"), str)
            or not producer["context"]
            or not _positive_integer(producer.get("app_id"))
        ):
            raise AuditInputError(
                "GitHub branch protection producer is invalid"
            )
        if producer["context"] == policy.ci_check:
            matches.append(producer["app_id"])
    if len(matches) > 1:
        raise AuditInputError(
            "GitHub branch protection producer is ambiguous"
        )
    return matches[0] if matches else None


def _validate_branch_protection_shape(value: object) -> None:
    if not isinstance(value, dict):
        raise AuditInputError("GitHub branch protection is invalid")
    for key in (
        "required_status_checks",
        "enforce_admins",
        "required_pull_request_reviews",
        "required_conversation_resolution",
        "allow_force_pushes",
        "allow_deletions",
    ):
        if key in value and not isinstance(value[key], dict):
            raise AuditInputError(
                "GitHub branch protection is invalid"
            )
    checks = value.get("required_status_checks")
    if isinstance(checks, dict):
        if "strict" in checks and type(checks["strict"]) is not bool:
            raise AuditInputError(
                "GitHub branch protection is invalid"
            )
        contexts = checks.get("contexts")
        if contexts is not None and (
            not isinstance(contexts, list)
            or not all(isinstance(item, str) for item in contexts)
        ):
            raise AuditInputError(
                "GitHub branch protection is invalid"
            )
    reviews = value.get("required_pull_request_reviews")
    if isinstance(reviews, dict):
        count = reviews.get("required_approving_review_count")
        if count is not None and (
            type(count) is not int or count < 0
        ):
            raise AuditInputError(
                "GitHub branch protection is invalid"
            )
    for key in (
        "enforce_admins",
        "required_conversation_resolution",
        "allow_force_pushes",
        "allow_deletions",
    ):
        nested = value.get(key)
        if isinstance(nested, dict) and (
            "enabled" in nested
            and type(nested["enabled"]) is not bool
        ):
            raise AuditInputError(
                "GitHub branch protection is invalid"
            )


def _tag_ruleset_details(
    repository: str,
    values: object,
    runner: Runner,
) -> list[object]:
    if not isinstance(values, list):
        raise AuditInputError("GitHub ruleset response is invalid")
    details: list[object] = []
    seen: set[int] = set()
    for value in values:
        if (
            not isinstance(value, dict)
            or not _positive_integer(value.get("id"))
            or value["id"] in seen
            or value.get("target") not in {"branch", "tag", "push"}
            or value.get("enforcement")
            not in {"active", "evaluate", "disabled"}
        ):
            raise AuditInputError("GitHub ruleset response is invalid")
        seen.add(value["id"])
        if value["target"] != "tag":
            continue
        detail = _gh_json(
            repository, f"/rulesets/{value['id']}", runner
        )
        if (
            not isinstance(detail, dict)
            or detail.get("id") != value["id"]
            or detail.get("target") != value["target"]
            or detail.get("enforcement") != value["enforcement"]
            or detail.get("target") != "tag"
            or detail.get("enforcement")
            not in {"active", "evaluate", "disabled"}
        ):
            raise AuditInputError("GitHub ruleset detail is invalid")
        details.append(detail)
    return details


def _tag_glob_regex(pattern: str) -> re.Pattern[str]:
    if (
        not isinstance(pattern, str)
        or not pattern.startswith("refs/tags/")
        or _has_control_characters(pattern)
    ):
        raise AuditInputError("GitHub tag protection pattern is invalid")
    suffix = pattern.removeprefix("refs/tags/")
    try:
        prefix, wildcard = _protected_tag_glob_parts(suffix)
    except ValueError:
        raise AuditInputError(
            "GitHub tag protection pattern is unsupported"
        ) from None
    if wildcard:
        expression = re.escape(prefix) + r"[^/]*"
    else:
        expression = re.escape(prefix)
    return re.compile(expression)


def _tag_ruleset_satisfies(
    ruleset: object,
    pattern: str,
    policy: Policy,
    producer_app_id: int | None = None,
) -> bool:
    if (
        not isinstance(ruleset, dict)
        or not _positive_integer(ruleset.get("id"))
        or ruleset.get("target") != "tag"
        or ruleset.get("enforcement") != "active"
    ):
        return False
    conditions = ruleset.get("conditions")
    ref_name = (
        conditions.get("ref_name")
        if isinstance(conditions, dict)
        else None
    )
    include = (
        ref_name.get("include") if isinstance(ref_name, dict) else None
    )
    exclude = (
        ref_name.get("exclude") if isinstance(ref_name, dict) else None
    )
    rules = ruleset.get("rules")
    bypass_actors = ruleset.get("bypass_actors")
    if (
        not isinstance(include, list)
        or not all(isinstance(item, str) for item in include)
        or not isinstance(exclude, list)
        or not all(isinstance(item, str) for item in exclude)
        or not isinstance(rules, list)
        or not isinstance(bypass_actors, list)
    ):
        return False
    for item in include:
        _tag_glob_regex(item)
    for item in exclude:
        _tag_glob_regex(item)
    if exclude or bypass_actors:
        return False
    rule_types: set[str] = set()
    check_rule = False
    for rule in rules:
        if (
            not isinstance(rule, dict)
            or not isinstance(rule.get("type"), str)
        ):
            return False
        rule_type = rule["type"]
        if rule_type in rule_types:
            return False
        rule_types.add(rule_type)
        if rule_type != "required_status_checks":
            continue
        parameters = rule.get("parameters")
        required = (
            parameters.get("required_status_checks")
            if isinstance(parameters, dict)
            else None
        )
        strict = (
            parameters.get("strict_required_status_checks_policy")
            if isinstance(parameters, dict)
            else None
        )
        if required is None:
            continue
        if not isinstance(required, list):
            raise AuditInputError(
                "GitHub tag protection producer is invalid"
            )
        producer_matches: list[int] = []
        for item in required:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("context"), str)
                or not item["context"]
                or not _positive_integer(item.get("integration_id"))
            ):
                raise AuditInputError(
                    "GitHub tag protection producer is invalid"
                )
            if item["context"] == policy.ci_check:
                producer_matches.append(item["integration_id"])
        if len(producer_matches) > 1:
            raise AuditInputError(
                "GitHub tag protection producer is ambiguous"
            )
        check_rule = (
            strict is True
            and len(producer_matches) == 1
            and (
                producer_app_id is None
                or producer_matches[0] == producer_app_id
            )
        )
    return (
        "refs/tags/" + pattern in include
        and {"deletion", "non_fast_forward"} <= rule_types
        and check_rule
    )


def tag_protection_satisfies(
    values: object,
    policy: Policy,
    tags: Sequence[str] = (),
    producer_app_id: int | None = None,
) -> bool:
    if not isinstance(values, list):
        return False
    for pattern in policy.protected_tag_patterns:
        _tag_glob_regex("refs/tags/" + pattern)
    for value in values:
        if not isinstance(value, dict):
            return False
        conditions = value.get("conditions")
        ref_name = (
            conditions.get("ref_name")
            if isinstance(conditions, dict)
            else None
        )
        include = (
            ref_name.get("include")
            if isinstance(ref_name, dict)
            else None
        )
        exclude = (
            ref_name.get("exclude")
            if isinstance(ref_name, dict)
            else None
        )
        for patterns in (include, exclude):
            if (
                not isinstance(patterns, list)
                or not all(
                    isinstance(pattern, str)
                    for pattern in patterns
                )
            ):
                raise AuditInputError(
                    "GitHub tag protection pattern is invalid"
                )
            for pattern in patterns:
                _tag_glob_regex(pattern)
    if not policy.protected_tag_patterns:
        return False
    safe_rulesets = [
        value
        for value in values
        if any(
            _tag_ruleset_satisfies(
                value, pattern, policy, producer_app_id
            )
            for pattern in policy.protected_tag_patterns
        )
    ]
    protected_patterns = all(
        any(
            _tag_ruleset_satisfies(
                ruleset, pattern, policy, producer_app_id
            )
            for ruleset in values
        )
        for pattern in policy.protected_tag_patterns
    )
    actual_tags = all(
        any(
            any(
                _tag_glob_regex(include).fullmatch(tag) is not None
                for include in ruleset["conditions"]["ref_name"]["include"]
            )
            for ruleset in safe_rulesets
        )
        for tag in tags
    )
    return protected_patterns and actual_tags


def _github_controls(
    repository: str,
    policy: Policy,
    runner: Runner,
) -> _GitHubControls:
    metadata = _gh_json(repository, "", runner)
    if not isinstance(metadata, dict):
        raise AuditInputError("GitHub metadata is invalid")
    owner_name, repository_name = repository.split("/", 1)
    owner = metadata.get("owner")
    visibility = metadata.get("visibility")
    default_branch = metadata.get("default_branch")
    enabled_surfaces = (
        metadata.get("has_wiki"),
        metadata.get("has_discussions"),
        metadata.get("has_pages"),
    )
    security = metadata.get("security_and_analysis")
    secret_scanning = (
        security.get("secret_scanning")
        if isinstance(security, dict)
        else None
    )
    push_protection = (
        security.get("secret_scanning_push_protection")
        if isinstance(security, dict)
        else None
    )
    secret_status = (
        secret_scanning.get("status")
        if isinstance(secret_scanning, dict)
        else None
    )
    push_status = (
        push_protection.get("status")
        if isinstance(push_protection, dict)
        else None
    )
    if (
        not _positive_integer(metadata.get("id"))
        or metadata.get("full_name") != repository
        or metadata.get("name") != repository_name
        or not isinstance(owner, dict)
        or owner.get("login") != owner_name
        or visibility not in {"private", "public", "internal"}
        or not isinstance(default_branch, str)
        or not default_branch
        or _has_control_characters(default_branch)
        or not all(type(value) is bool for value in enabled_surfaces)
        or secret_status not in {"enabled", "disabled"}
        or push_status not in {"enabled", "disabled"}
    ):
        raise AuditInputError("GitHub metadata is invalid")

    branches = _github_branches(
        _gh_list(repository, "/branches?per_page=100", runner)
    )
    tags = _github_tags(
        _gh_list(repository, "/tags?per_page=100", runner)
    )
    intended_branches = tuple(
        sorted(
            ref.removeprefix("refs/heads/")
            for ref in policy.public_branches
        )
    )
    protections: list[tuple[str, object]] = []
    branch_protected = True
    branch_producers: list[int] = []
    for branch in intended_branches:
        protection = _gh_json(
            repository,
            "/branches/"
            + urllib.parse.quote(branch, safe="")
            + "/protection",
            runner,
        )
        _validate_branch_protection_shape(protection)
        branch_protected = (
            branch_protected
            and branch_protection_satisfies(protection, policy)
        )
        producer = _branch_protection_producer(protection, policy)
        if producer is None:
            branch_protected = False
        else:
            branch_producers.append(producer)
        protections.append((branch, protection))
    producer_ids = set(branch_producers)
    if len(branch_producers) != len(intended_branches):
        producer_app_id = None
    elif len(producer_ids) == 1:
        producer_app_id = next(iter(producer_ids))
    else:
        producer_app_id = None
        branch_protected = False

    ruleset_summaries = _gh_list(
        repository, "/rulesets?per_page=100", runner
    )
    rulesets = _tag_ruleset_details(
        repository, ruleset_summaries, runner
    )
    tags_protected = tag_protection_satisfies(
        rulesets, policy, tuple(tags), producer_app_id
    )

    vulnerability = _gh_json(
        repository,
        "/private-vulnerability-reporting",
        runner,
    )
    if (
        not isinstance(vulnerability, dict)
        or type(vulnerability.get("enabled")) is not bool
    ):
        raise AuditInputError(
            "GitHub vulnerability reporting is invalid"
        )

    actions = _gh_json(
        repository,
        "/actions/permissions/workflow",
        runner,
    )
    if (
        not isinstance(actions, dict)
        or actions.get("default_workflow_permissions")
        not in {"read", "write"}
        or type(actions.get("can_approve_pull_request_reviews"))
        is not bool
    ):
        raise AuditInputError(
            "GitHub Actions permissions are invalid"
        )

    try:
        control_digest = hash_bytes(
            canonical_json(
                {
                    "metadata": {
                        "id": metadata["id"],
                        "full_name": metadata["full_name"],
                        "name": metadata["name"],
                        "owner": owner["login"],
                        "visibility": visibility,
                        "default_branch": default_branch,
                        "has_wiki": enabled_surfaces[0],
                        "has_discussions": enabled_surfaces[1],
                        "has_pages": enabled_surfaces[2],
                        "secret_scanning": secret_status,
                        "push_protection": push_status,
                    },
                    "branches": sorted(branches.items()),
                    "tags": sorted(tags.items()),
                    "protections": [
                        [branch, hash_bytes(canonical_json(value))]
                        for branch, value in protections
                    ],
                    "ruleset_summaries": sorted(
                        hash_bytes(canonical_json(value))
                        for value in ruleset_summaries
                    ),
                    "ruleset_details": sorted(
                        hash_bytes(canonical_json(value))
                        for value in rulesets
                    ),
                    "vulnerability_reporting": vulnerability["enabled"],
                    "actions_permission": actions[
                        "default_workflow_permissions"
                    ],
                    "actions_can_approve": actions[
                        "can_approve_pull_request_reviews"
                    ],
                    "producer_app_id": producer_app_id,
                }
            )
        )
    except (TypeError, ValueError, RecursionError):
        raise AuditInputError("GitHub controls are invalid") from None

    return _GitHubControls(
        visibility,
        default_branch,
        enabled_surfaces,
        secret_status,
        push_status,
        tuple(sorted(branches.items())),
        tuple(sorted(tags.items())),
        branch_protected,
        tags_protected,
        vulnerability["enabled"],
        actions["default_workflow_permissions"],
        actions["can_approve_pull_request_reviews"],
        producer_app_id,
        control_digest,
    )


def _zip_has_exact_end(payload: bytes) -> bool:
    minimum = 22
    maximum = min(len(payload), 65_557)
    offset = payload.rfind(b"PK\x05\x06", len(payload) - maximum)
    if offset < 0 or len(payload) - offset < minimum:
        return False
    comment_length = int.from_bytes(
        payload[offset + 20:offset + 22], "little"
    )
    return (
        comment_length == 0
        and offset + minimum == len(payload)
    )


def _scan_action_log_entry(entry) -> bool:
    overlap = b""
    total = 0
    while True:
        chunk = entry.read(ACTION_LOG_READ_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > ACTION_LOG_ENTRY_LIMIT:
            raise AuditInputError("GitHub Actions log entry is oversized")
        normalized = re.sub(rb"\s+", b" ", chunk)
        window = overlap + normalized
        if any(pattern.search(window) for pattern in ACTION_LOG_MARKERS):
            return True
        overlap = window[-ACTION_LOG_SCAN_OVERLAP_BYTES:]
    return False


def _scan_action_log_archive(payload: bytes) -> bool:
    if (
        not payload
        or len(payload) > ACTION_LOG_ARCHIVE_LIMIT
        or not payload.startswith(b"PK\x03\x04")
        or not _zip_has_exact_end(payload)
    ):
        raise AuditInputError("GitHub Actions log archive is invalid")
    matched = False
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            infos = archive.infolist()
            if not 1 <= len(infos) <= ACTION_LOG_ENTRY_COUNT_LIMIT:
                raise AuditInputError(
                    "GitHub Actions log archive has invalid entries"
                )
            names: set[str] = set()
            total_uncompressed = 0
            total_compressed = 0
            for info in infos:
                name = info.filename
                path = PurePosixPath(name)
                mode = info.external_attr >> 16
                raw_parts = name.split("/")
                if info.is_dir() and raw_parts[-1] == "":
                    raw_parts = raw_parts[:-1]
                if (
                    not isinstance(name, str)
                    or not name
                    or "\\" in name
                    or _has_control_characters(name)
                    or path.is_absolute()
                    or any(
                        part in {"", ".", ".."} for part in raw_parts
                    )
                    or re.match(r"^[A-Za-z]:", name) is not None
                    or name in names
                    or info.flag_bits & 0x1
                    or info.comment
                    or info.extra
                    or stat.S_ISLNK(mode)
                    or info.compress_type not in {
                        zipfile.ZIP_STORED,
                        zipfile.ZIP_DEFLATED,
                    }
                    or info.file_size < 0
                    or info.compress_size < 0
                ):
                    raise AuditInputError(
                        "GitHub Actions log entry is unsafe"
                    )
                names.add(name)
                if info.is_dir():
                    continue
                if (
                    info.file_size > ACTION_LOG_ENTRY_LIMIT
                    or (
                        info.file_size > ACTION_LOG_READ_CHUNK_BYTES
                        and info.file_size
                        > max(1, info.compress_size)
                        * ACTION_LOG_COMPRESSION_RATIO_LIMIT
                    )
                ):
                    raise AuditInputError(
                        "GitHub Actions log entry exceeded its bound"
                    )
                total_uncompressed += info.file_size
                total_compressed += info.compress_size
                if (
                    total_uncompressed > ACTION_LOG_TOTAL_LIMIT
                    or total_compressed > ACTION_LOG_ARCHIVE_LIMIT
                ):
                    raise AuditInputError(
                        "GitHub Actions log archive exceeded its bound"
                    )
                with archive.open(info) as entry:
                    entry_matched = _scan_action_log_entry(entry)
                    if entry.read(1):
                        raise AuditInputError(
                            "GitHub Actions log entry exceeded its bound"
                        )
                matched = matched or entry_matched
    except (
        OSError,
        RuntimeError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ):
        raise AuditInputError(
            "GitHub Actions log archive is invalid"
        ) from None
    return matched


def _action_log_findings(
    repository: str,
    runs: Sequence[dict[str, object]],
    runner: Runner,
) -> list[Finding]:
    findings: list[Finding] = []
    for run in runs:
        run_id = run["id"]
        payload = _github_result(
            (
                "gh",
                "api",
                _github_repository_path(repository)
                + f"/actions/runs/{run_id}/logs",
            ),
            runner,
            limit=ACTION_LOG_ARCHIVE_LIMIT,
        )
        if _scan_action_log_archive(payload):
            findings.append(
                _github_finding(
                    "github.actions-log-secret",
                    "github-surface",
                )
            )
    return findings


def _package_findings(
    repository: str,
    runner: Runner,
) -> list[Finding]:
    owner, name = repository.split("/", 1)
    payload = _github_result(
        (
            "gh",
            "api",
            "graphql",
            "-f",
            f"query={PACKAGE_QUERY}",
            "-F",
            f"owner={owner}",
            "-F",
            f"name={name}",
        ),
        runner,
    )
    value = _github_json_payload(payload)
    if isinstance(value, dict) and "errors" in value:
        raise AuditInputError("GitHub package surface is incomplete")
    data = value.get("data") if isinstance(value, dict) else None
    repository_value = (
        data.get("repository") if isinstance(data, dict) else None
    )
    packages = (
        repository_value.get("packages")
        if isinstance(repository_value, dict)
        else None
    )
    nodes = packages.get("nodes") if isinstance(packages, dict) else None
    page_info = (
        packages.get("pageInfo") if isinstance(packages, dict) else None
    )
    if (
        not isinstance(nodes, list)
        or len(nodes) > 100
        or not isinstance(page_info, dict)
        or page_info.get("hasNextPage") is not False
        or page_info.get("endCursor") is not None
    ):
        raise AuditInputError("GitHub package surface is incomplete")
    seen: set[tuple[str, str]] = set()
    for node in nodes:
        if (
            not isinstance(node, dict)
            or not isinstance(node.get("name"), str)
            or not node["name"]
            or not isinstance(node.get("packageType"), str)
            or not node["packageType"]
            or _has_control_characters(node["name"])
            or _has_control_characters(node["packageType"])
        ):
            raise AuditInputError("GitHub package surface is invalid")
        identity = (node["name"], node["packageType"])
        if identity in seen:
            raise AuditInputError("GitHub package surface is duplicated")
        seen.add(identity)
    if not nodes:
        return []
    return [_github_finding("github.package", "github-surface")]


def _commit_identity_findings(
    repository: str,
    references: Sequence[str],
    policy: Policy,
    runner: Runner,
) -> list[Finding]:
    approved = tuple(
        re.compile(pattern) for pattern in policy.public_email_patterns
    )
    unapproved = False
    for reference in references:
        query = urllib.parse.urlencode(
            {"sha": reference, "per_page": "100"},
            quote_via=urllib.parse.quote,
            safe="",
        )
        commits = _gh_list(
            repository,
            "/commits?" + query,
            runner,
        )
        if not commits:
            raise AuditInputError(
                "GitHub commit history is incomplete"
            )
        seen: set[str] = set()
        for item in commits:
            commit = item.get("commit") if isinstance(item, dict) else None
            sha = item.get("sha") if isinstance(item, dict) else None
            if (
                not _valid_github_sha(sha)
                or sha in seen
                or not isinstance(commit, dict)
            ):
                raise AuditInputError(
                    "GitHub commit identity is incomplete"
                )
            seen.add(sha)
            for role in ("author", "committer"):
                identity = commit.get(role)
                email = (
                    identity.get("email")
                    if isinstance(identity, dict)
                    else None
                )
                if (
                    not isinstance(email, str)
                    or not email
                    or len(email) > 320
                    or _has_control_characters(email)
                ):
                    raise AuditInputError(
                        "GitHub commit identity is incomplete"
                    )
                if not any(pattern.fullmatch(email) for pattern in approved):
                    unapproved = True
    if not unapproved:
        return []
    return [
        _github_finding(
            "github.commit-identity", "github-surface"
        )
    ]


def _surface_findings(
    repository: str,
    policy: Policy,
    branches: Mapping[str, str],
    tags: Mapping[str, str],
    runner: Runner,
) -> list[Finding]:
    findings: dict[str, Finding] = {}
    pulls = _identity_items(
        _gh_list(
            repository,
            "/pulls?state=all&per_page=100",
            runner,
        ),
        "id",
    )
    if len(pulls) > GITHUB_MAX_NESTED_SURFACES:
        raise AuditInputError(
            "GitHub pull-request surface exceeded its bound"
        )
    pull_numbers: set[int] = set()
    for pull in pulls:
        if (
            not _positive_integer(pull.get("number"))
            or pull["number"] in pull_numbers
        ):
            raise AuditInputError("GitHub pull request is invalid")
        pull_numbers.add(pull["number"])
        reviews = _identity_items(
            _gh_list(
                repository,
                f"/pulls/{pull['number']}/reviews?per_page=100",
                runner,
            ),
            "id",
        )
        if reviews:
            _add_github_finding(
                findings, "github.review", "github-surface"
            )
    if pulls:
        _add_github_finding(
            findings, "github.pull-request", "github-surface"
        )
    for endpoint, rule_id, identity in GITHUB_EMPTY_SURFACES:
        values = _identity_items(
            _gh_list(repository, endpoint, runner), identity
        )
        if values:
            _add_github_finding(
                findings, rule_id, "github-surface"
            )
    artifacts = _identity_items(
        _gh_list(
            repository,
            "/actions/artifacts?per_page=100",
            runner,
            field="artifacts",
            total_field="total_count",
        ),
        "id",
    )
    if artifacts:
        _add_github_finding(
            findings, "github.artifact", "github-surface"
        )
    raw_runs = _gh_list(
        repository,
        "/actions/runs?per_page=100",
        runner,
        field="workflow_runs",
        total_field="total_count",
    )
    runs = _identity_items(raw_runs, "id")
    if len(runs) > GITHUB_MAX_NESTED_SURFACES:
        raise AuditInputError(
            "GitHub workflow-run surface exceeded its bound"
        )
    typed_runs: list[dict[str, object]] = []
    for run in runs:
        if (
            not _valid_github_sha(run.get("head_sha"))
            or run.get("status") != "completed"
            or not isinstance(run.get("conclusion"), str)
            or not run["conclusion"]
            or _has_control_characters(run["conclusion"])
            or not isinstance(run.get("path"), str)
            or not run["path"]
            or _has_control_characters(run["path"])
            or run["path"].startswith("/")
            or "\\" in run["path"]
            or any(
                part in {"", ".", ".."}
                for part in run["path"].split("/")
            )
        ):
            raise AuditInputError("GitHub workflow run is incomplete")
        typed_runs.append(run)
    for finding in _action_log_findings(
        repository, typed_runs, runner
    ):
        findings.setdefault(finding.rule_id, finding)
    references = tuple(branches) + tuple(tags)
    if len(references) > GITHUB_MAX_REFS:
        raise AuditInputError(
            "GitHub public ref surface exceeded its bound"
        )
    for finding in _commit_identity_findings(
        repository, references, policy, runner
    ):
        findings.setdefault(finding.rule_id, finding)
    for finding in _package_findings(repository, runner):
        findings.setdefault(finding.rule_id, finding)
    return list(findings.values())


def _stable_surface_findings(
    repository: str,
    policy: Policy,
    branches: Mapping[str, str],
    tags: Mapping[str, str],
    runner: Runner,
) -> list[Finding]:
    first_runner = _TranscriptRunner(runner)
    first = _surface_findings(
        repository, policy, branches, tags, first_runner
    )
    second_runner = _TranscriptRunner(runner)
    second = _surface_findings(
        repository, policy, branches, tags, second_runner
    )
    if (
        tuple(first_runner.evidence)
        != tuple(second_runner.evidence)
        or tuple(first) != tuple(second)
    ):
        raise AuditInputError(
            "GitHub retained surfaces changed during inspection"
        )
    return first


def _remote_ref_matches(
    repository: str,
    ref: str,
    object_id: str,
    runner: Runner,
) -> bool:
    remote_ref = _gh_json(
        repository,
        "/git/ref/"
        + urllib.parse.quote(ref.removeprefix("refs/"), safe=""),
        runner,
    )
    remote_object = (
        remote_ref.get("object")
        if isinstance(remote_ref, dict)
        else None
    )
    return (
        isinstance(remote_ref, dict)
        and remote_ref.get("ref") == ref
        and isinstance(remote_object, dict)
        and remote_object.get("sha") == object_id
        and (
            ref.startswith("refs/heads/")
            and remote_object.get("type") == "commit"
            or ref.startswith("refs/tags/")
            and remote_object.get("type") in {"commit", "tag"}
        )
    )


def _candidate_findings(
    repository: str,
    expected_refs: Mapping[str, str],
    policy: Policy,
    runner: Runner,
    producer_app_id: int | None,
) -> list[Finding]:
    candidate_valid = producer_app_id is not None
    for ref, object_id in expected_refs.items():
        if (
            not isinstance(ref, str)
            or not ref.startswith(("refs/heads/", "refs/tags/"))
            or _has_control_characters(ref)
            or not _valid_github_sha(object_id)
        ):
            raise AuditInputError("GitHub candidate refs are invalid")
        if not _remote_ref_matches(
            repository, ref, object_id, runner
        ):
            candidate_valid = False
    for ref, object_id in expected_refs.items():
        if not ref.startswith("refs/heads/"):
            continue
        checks = _gh_list(
            repository,
            (
                f"/commits/{object_id}/check-runs"
                "?filter=latest&per_page=100"
            ),
            runner,
            field="check_runs",
            total_field="total_count",
        )
        required_checks: list[dict[str, object]] = []
        seen: set[int] = set()
        for check in checks:
            if (
                not isinstance(check, dict)
                or not _positive_integer(check.get("id"))
                or check["id"] in seen
                or not isinstance(check.get("name"), str)
                or not _valid_github_sha(check.get("head_sha"))
                or not isinstance(check.get("status"), str)
                or not isinstance(check.get("conclusion"), str)
            ):
                raise AuditInputError(
                    "GitHub candidate check is invalid"
                )
            seen.add(check["id"])
            if check["name"] == policy.ci_check:
                required_checks.append(check)
        if len(required_checks) > 1:
            raise AuditInputError(
                "GitHub candidate check is ambiguous"
            )
        required_suite_id: int | None = None
        if required_checks:
            required_check = required_checks[0]
            app = required_check.get("app")
            check_suite = required_check.get("check_suite")
            if (
                not isinstance(app, dict)
                or not _positive_integer(app.get("id"))
                or not isinstance(check_suite, dict)
                or not _positive_integer(check_suite.get("id"))
            ):
                raise AuditInputError(
                    "GitHub candidate producer is invalid"
                )
            required_suite_id = check_suite["id"]
            if (
                required_check["head_sha"] != object_id
                or required_check["status"] != "completed"
                or required_check["conclusion"] != "success"
                or required_check["app"]["id"] != producer_app_id
            ):
                candidate_valid = False
        else:
            candidate_valid = False
        runs = _gh_list(
            repository,
            "/actions/runs?per_page=100",
            runner,
            field="workflow_runs",
            total_field="total_count",
        )
        workflow_matches: list[dict[str, object]] = []
        seen_runs: set[int] = set()
        for run in runs:
            if (
                not isinstance(run, dict)
                or not _positive_integer(run.get("id"))
                or run["id"] in seen_runs
                or not _valid_github_sha(run.get("head_sha"))
                or not isinstance(run.get("path"), str)
                or not isinstance(run.get("status"), str)
                or not isinstance(run.get("conclusion"), str)
            ):
                raise AuditInputError(
                    "GitHub candidate workflow is invalid"
                )
            seen_runs.add(run["id"])
            if (
                run["head_sha"] == object_id
                and run["path"] == policy.ci_workflow
            ):
                workflow_matches.append(run)
        if len(workflow_matches) > 1:
            raise AuditInputError(
                "GitHub candidate workflow is ambiguous"
            )
        if workflow_matches:
            workflow = workflow_matches[0]
            if not _positive_integer(workflow.get("check_suite_id")):
                raise AuditInputError(
                    "GitHub candidate workflow producer is invalid"
                )
            if (
                workflow["status"] != "completed"
                or workflow["conclusion"] != "success"
                or required_suite_id is None
                or workflow["check_suite_id"] != required_suite_id
            ):
                candidate_valid = False
        else:
            candidate_valid = False
    for ref, object_id in expected_refs.items():
        if not _remote_ref_matches(
            repository, ref, object_id, runner
        ):
            candidate_valid = False
    if candidate_valid:
        return []
    return [
        _github_finding(
            "github.candidate", "github-control"
        )
    ]


def _stable_candidate_findings(
    repository: str,
    expected_refs: Mapping[str, str],
    policy: Policy,
    runner: Runner,
    producer_app_id: int | None,
) -> list[Finding]:
    first_runner = _TranscriptRunner(runner)
    first = _candidate_findings(
        repository,
        expected_refs,
        policy,
        first_runner,
        producer_app_id,
    )
    second_runner = _TranscriptRunner(runner)
    second = _candidate_findings(
        repository,
        expected_refs,
        policy,
        second_runner,
        producer_app_id,
    )
    if (
        tuple(first_runner.evidence)
        != tuple(second_runner.evidence)
        or tuple(first) != tuple(second)
    ):
        raise AuditInputError(
            "GitHub candidate evidence changed during inspection"
        )
    return first


def inspect_github_identity(
    repository: str,
    policy: Policy,
    runner: Runner = run_github_command,
    *,
    expected_refs: Mapping[str, str] | None = None,
) -> GitHubState:
    incomplete = GitHubState(
        "",
        "",
        False,
        (
            _github_finding(
                "github.surface.incomplete", "github"
            ),
        ),
        False,
    )
    try:
        tag_languages_covered = _tag_policy_languages_covered(
            policy.public_tag_patterns,
            policy.protected_tag_patterns,
        )
    except (AttributeError, TypeError, ValueError):
        return incomplete
    if (
        not isinstance(policy, Policy)
        or repository != policy.repository
        or len(policy.public_branches) > GITHUB_MAX_REFS
        or len(policy.public_tag_patterns) > GITHUB_MAX_REFS
        or len(policy.protected_branches) > GITHUB_MAX_REFS
        or len(policy.protected_tag_patterns) > GITHUB_MAX_REFS
        or set(policy.protected_branches)
        != {
            ref.removeprefix("refs/heads/")
            for ref in policy.public_branches
        }
        or not tag_languages_covered
    ):
        return incomplete
    runner = _InspectionRunner(runner)
    findings: dict[str, Finding] = {}
    try:
        _github_authenticated(runner)
        controls = _github_controls(repository, policy, runner)
        branches = dict(controls.branches)
        tags = dict(controls.tags)
        allowed_branches = {
            ref.removeprefix("refs/heads/")
            for ref in policy.public_branches
        }
        if set(branches) != allowed_branches:
            _add_github_finding(findings, "github.ref")
        expected_default = policy.public_branches[
            0
        ].removeprefix("refs/heads/")
        if controls.default_branch != expected_default:
            _add_github_finding(
                findings, "github.default-branch"
            )
        tag_patterns = tuple(
            re.compile(pattern)
            for pattern in policy.public_tag_patterns
        )
        if any(
            not any(
                pattern.fullmatch("refs/tags/" + tag)
                for pattern in tag_patterns
            )
            for tag in tags
        ):
            _add_github_finding(findings, "github.ref")
        if controls.visibility == "internal":
            _add_github_finding(
                findings, "github.visibility"
            )
        if any(controls.enabled_surfaces):
            _add_github_finding(
                findings,
                "github.surface-enabled",
                "github-surface",
            )
        if (
            controls.secret_scanning != "enabled"
            or controls.push_protection != "enabled"
        ):
            _add_github_finding(
                findings, "github.secret-scanning"
            )
        if (
            not controls.branch_protected
            or not controls.tags_protected
        ):
            _add_github_finding(
                findings, "github.protection"
            )
        if controls.vulnerability_reporting is not True:
            _add_github_finding(
                findings, "github.vulnerability-reporting"
            )
        if (
            controls.actions_permission != "read"
            or controls.actions_can_approve is not False
        ):
            _add_github_finding(
                findings, "github.actions-permissions"
            )
        for finding in _stable_surface_findings(
            repository, policy, branches, tags, runner
        ):
            findings.setdefault(finding.rule_id, finding)
        candidate_findings: list[Finding] = []
        if expected_refs is not None:
            expected_names = {
                ref.removeprefix("refs/heads/")
                for ref in expected_refs
                if ref.startswith("refs/heads/")
            }
            expected_tags = {
                ref.removeprefix("refs/tags/")
                for ref in expected_refs
                if ref.startswith("refs/tags/")
            }
            if (
                expected_names != set(branches)
                or expected_tags != set(tags)
            ):
                candidate_findings = [
                    _github_finding(
                        "github.candidate", "github-control"
                    )
                ]
            else:
                candidate_findings = _stable_candidate_findings(
                    repository,
                    expected_refs,
                    policy,
                    runner,
                    controls.producer_app_id,
                )
            for finding in candidate_findings:
                findings.setdefault(finding.rule_id, finding)
        end_controls = _github_controls(repository, policy, runner)
        if end_controls.digest != controls.digest:
            raise AuditInputError(
                "GitHub controls changed during inspection"
            )
    except (
        AuditInputError,
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        RecursionError,
    ):
        return incomplete
    ordered = tuple(
        findings[key] for key in sorted(findings)
    )
    return GitHubState(
        controls.visibility,
        controls.default_branch,
        True,
        ordered,
        expected_refs is not None and not candidate_findings,
    )


def inspect_github(
    snapshot: RepositorySnapshot,
    policy: Policy,
    runner: Runner = run_github_command,
) -> GitHubState:
    if (
        not isinstance(snapshot, RepositorySnapshot)
        or not isinstance(policy, Policy)
        or snapshot.public_branches != policy.public_branches
        or snapshot.public_tag_patterns != policy.public_tag_patterns
        or not snapshot.refs
        or len(snapshot.refs) != len(dict(snapshot.refs))
        or len(snapshot.refs) > GITHUB_MAX_REFS
    ):
        return GitHubState(
            "",
            "",
            False,
            (
                _github_finding(
                    "github.surface.incomplete", "github"
                ),
            ),
            False,
        )
    return inspect_github_identity(
        policy.repository,
        policy,
        runner,
        expected_refs=dict(snapshot.refs),
    )


FORBIDDEN_PATH_PARTS = {
    "AGENTS.md", "CLAUDE.md", "GEMINI.md", ".codex", ".claude",
    ".gemini", ".agents", ".superpowers", "docs/superpowers",
    "docs/agent-workflows.md"
}
ARCHIVE_SUFFIXES = {
    ".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".sql", ".sqlite", ".db", ".log", ".pcap", ".har"
}
PRIVATE_PATTERNS = (
    ("private.path", re.compile(
        rb"(?:^|[\s`\"'(=])(?:/(?:Users|home)/[A-Za-z0-9._-]+|"
        rb"[A-Za-z]:[\\/]+Users[\\/]+[A-Za-z0-9._-]+)"
    )),
    ("private.temp", re.compile(
        rb"(?:^|[\s`\"'(=])(?:/private)?/var/folders/[A-Za-z0-9_./-]+"
    )),
)
MAX_BLOB_BYTES = 10 * 1024 * 1024
MAX_LOCAL_CONFIG_BYTES = 1024 * 1024
MAX_GIT_METADATA_BYTES = 4096
MAX_FINDINGS_PER_RULE = 20
MAX_TOTAL_FINDINGS = 50
READ_CHUNK_BYTES = 64 * 1024
EMAIL_PATTERN = re.compile(
    rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)
IPV4_PATTERN = re.compile(
    rb"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])"
)
HOST_ASSIGNMENT_PATTERN = re.compile(
    rb"(?i)(?:host|hostname|server|endpoint)\s*[:=]\s*[\"']?"
    rb"(?:https?://)?((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})"
)
PUBLIC_HOSTS = {
    "github.com", "api.github.com", "raw.githubusercontent.com",
    "wordpress.org", "api.wordpress.org", "wp-cli.org",
    "go.dev", "pkg.go.dev", "schema.org", "json-schema.org",
    "shields.io", "localhost",
}
FORWARDED_LOCAL_CONFIG = {
    "core.repositoryformatversion": re.compile(r"[01]"),
    "extensions.objectformat": re.compile(r"sha1|sha256"),
    "extensions.refstorage": re.compile(r"files|reftable"),
}
DANGEROUS_LOCAL_CONFIG = re.compile(
    r"^(?:"
    r"core\.(?:fsmonitor|hookspath|worktree|sshcommand|gitproxy|"
    r"alternaterefscommand|pager)|"
    r"extensions\.worktreeconfig$|"
    r"(?:fsck|fetch\.fsck|receive\.fsck)\.|"
    r"(?:filter|alias|credential|include|includeif)\.|"
    r"diff\.external$|diff\..+\.command$|merge\..+\.driver$|"
    r"protocol\..+\.allow$"
    r")"
)


def git_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "LC_ALL": "C",
    }
    for name in ("SYSTEMROOT", "WINDIR", "TMPDIR", "TMP", "TEMP"):
        if value := os.environ.get(name):
            environment[name] = value
    return environment


def _git_command(
    root: Path,
    args: Sequence[str],
    repository_config: Sequence[tuple[str, str]]
) -> tuple[str, ...]:
    config_args = tuple(
        value
        for key, item in repository_config
        for value in ("-c", f"{key}={item}")
    )
    return ("git", *config_args, "-C", os.fspath(root), *args)


def _git_result(
    root: Path,
    *args: str,
    repository_config: Sequence[tuple[str, str]] = (),
    runner: Runner = run_command
) -> CommandResult:
    return runner(
        _git_command(root, args, repository_config),
        None,
        git_environment()
    )


def _git(
    root: Path,
    *args: str,
    repository_config: Sequence[tuple[str, str]] = (),
    runner: Runner = run_command
) -> bytes:
    result = _git_result(
        root, *args, repository_config=repository_config, runner=runner
    )
    if result.returncode != 0:
        raise AuditInputError(f"Git command failed: {' '.join(args[:2])}")
    return result.stdout


@dataclasses.dataclass(frozen=True)
class _RepositoryConfigSnapshot:
    values: tuple[tuple[str, str], ...]
    git_dir: Path
    common_dir: Path


def _trusted_git_metadata(
    info: os.stat_result,
    *,
    directory: bool
) -> bool:
    current_uid = getattr(os, "geteuid", lambda: info.st_uid)()
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    return (
        expected_kind(info.st_mode)
        and info.st_uid == current_uid
        and not stat.S_IMODE(info.st_mode) & 0o022
    )


def _git_metadata_directory_identity(
    info: os.stat_result
) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid)


def _repository_config_snapshot(
    root: Path,
    config_runner: ConfigParserRunner = run_config_parser
) -> _RepositoryConfigSnapshot:
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise AuditInputError(
            "no-follow local Git config access is unavailable"
        )
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | close_on_exec
    )
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | close_on_exec
    descriptors: list[int] = []
    reviewed_files: list[
        tuple[int, str, int, os.stat_result, bytes]
    ] = []
    directory_names: list[tuple[int, str, int, tuple[int, ...]]] = []

    def open_directory(path: Path) -> int:
        try:
            descriptor = _open_directory_nofollow(path)
        except AuditInputError as error:
            raise AuditInputError(
                "local Git config is unavailable or unsafe"
            ) from error
        descriptors.append(descriptor)
        info = os.fstat(descriptor)
        if not _trusted_git_metadata(info, directory=True):
            raise AuditInputError(
                "local Git config is unavailable or unsafe"
            )
        return descriptor

    def open_file(
        parent_descriptor: int,
        name: str,
        limit: int
    ) -> tuple[int, os.stat_result, bytes]:
        try:
            descriptor = os.open(
                name, file_flags, dir_fd=parent_descriptor
            )
        except OSError as error:
            raise AuditInputError(
                "local Git config is unavailable or unsafe"
            ) from error
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if (
            not _trusted_git_metadata(before, directory=False)
            or before.st_size > limit
        ):
            raise AuditInputError(
                "local Git config is not a bounded regular file"
            )
        reviewed = _read_bounded_descriptor(descriptor, limit)
        after = os.fstat(descriptor)
        try:
            current = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False
            )
        except OSError as error:
            raise AuditInputError(
                "local Git config changed during review"
            ) from error
        if (
            _config_stat_identity(before) != _config_stat_identity(after)
            or _config_stat_identity(before)
            != _config_stat_identity(current)
            or len(reviewed) != before.st_size
        ):
            raise AuditInputError(
                "local Git config changed during review"
            )
        reviewed_files.append(
            (parent_descriptor, name, descriptor, before, reviewed)
        )
        return descriptor, before, reviewed

    try:
        try:
            root_descriptor = os.open(os.fspath(root), directory_flags)
            descriptors.append(root_descriptor)
            try:
                git_descriptor = os.open(
                    ".git", directory_flags, dir_fd=root_descriptor
                )
            except OSError:
                _, _, pointer_payload = open_file(
                    root_descriptor, ".git", MAX_GIT_METADATA_BYTES
                )
                try:
                    pointer_text = pointer_payload.decode(
                        "utf-8", "strict"
                    )
                except UnicodeDecodeError as error:
                    raise AuditInputError(
                        "local Git config is unavailable or unsafe"
                    ) from error
                pointer_match = re.fullmatch(
                    r"gitdir: ([^\r\n]+)\n?", pointer_text
                )
                if pointer_match is None:
                    raise AuditInputError(
                        "local Git config is unavailable or unsafe"
                    )
                raw_git_dir = pointer_match.group(1)
                candidate_git_dir = Path(raw_git_dir)
                if (
                    _has_control_characters(raw_git_dir)
                    or ".." in candidate_git_dir.parts
                    or os.path.normpath(raw_git_dir) != raw_git_dir
                ):
                    raise AuditInputError(
                        "local Git config is unavailable or unsafe"
                    )
                git_dir = (
                    candidate_git_dir
                    if candidate_git_dir.is_absolute()
                    else root / candidate_git_dir
                )
                if (
                    not git_dir.is_absolute()
                    or git_dir.parent.name != "worktrees"
                    or not git_dir.name
                ):
                    raise AuditInputError(
                        "local Git config is unavailable or unsafe"
                    )
                common_dir = git_dir.parent.parent
                if common_dir == git_dir or common_dir == root:
                    raise AuditInputError(
                        "local Git config is unavailable or unsafe"
                    )
                common_descriptor = open_directory(common_dir)
                worktrees_descriptor = open_directory(git_dir.parent)
                git_descriptor = open_directory(git_dir)
                worktrees_info = os.fstat(worktrees_descriptor)
                git_info = os.fstat(git_descriptor)
                directory_names.extend((
                    (
                        common_descriptor, "worktrees",
                        worktrees_descriptor,
                        _git_metadata_directory_identity(worktrees_info)
                    ),
                    (
                        worktrees_descriptor, git_dir.name,
                        git_descriptor,
                        _git_metadata_directory_identity(git_info)
                    ),
                ))
                _, _, commondir_payload = open_file(
                    git_descriptor, "commondir", MAX_GIT_METADATA_BYTES
                )
                _, _, backlink_payload = open_file(
                    git_descriptor, "gitdir", MAX_GIT_METADATA_BYTES
                )
                if (
                    commondir_payload != b"../..\n"
                    or backlink_payload
                    != os.fsencode(os.fspath(root / ".git")) + b"\n"
                ):
                    raise AuditInputError(
                        "local Git config is unavailable or unsafe"
                    )
            else:
                descriptors.append(git_descriptor)
                git_info = os.fstat(git_descriptor)
                if not _trusted_git_metadata(git_info, directory=True):
                    raise AuditInputError(
                        "local Git config is unavailable or unsafe"
                    )
                git_dir = root / ".git"
                common_dir = git_dir
                common_descriptor = git_descriptor
                directory_names.append((
                    root_descriptor, ".git", git_descriptor,
                    _git_metadata_directory_identity(git_info)
                ))
            config_descriptor, before, reviewed = open_file(
                common_descriptor, "config", MAX_LOCAL_CONFIG_BYTES
            )
        except OSError as error:
            raise AuditInputError(
                "local Git config is unavailable or unsafe"
            ) from error
        result = config_runner((
            "git", "config", "--file", "-", "--no-includes",
            "--null", "--list"
        ), None, git_environment(), reviewed)
        for (
            parent_descriptor, name, descriptor, reviewed_info,
            reviewed_payload
        ) in reviewed_files:
            os.lseek(descriptor, 0, os.SEEK_SET)
            reread = _read_bounded_descriptor(
                descriptor,
                MAX_LOCAL_CONFIG_BYTES
                if name == "config"
                else MAX_GIT_METADATA_BYTES
            )
            after_parse = os.fstat(descriptor)
            try:
                current = os.stat(
                    name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False
                )
            except OSError as error:
                raise AuditInputError(
                    "local Git config changed during parsing"
                ) from error
            if (
                reviewed_payload != reread
                or _config_stat_identity(reviewed_info)
                != _config_stat_identity(after_parse)
                or _config_stat_identity(reviewed_info)
                != _config_stat_identity(current)
            ):
                raise AuditInputError(
                    "local Git config changed during parsing"
                )
        for parent_descriptor, name, descriptor, identity in directory_names:
            try:
                current = os.stat(
                    name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False
                )
            except OSError as error:
                raise AuditInputError(
                    "local Git config changed during parsing"
                ) from error
            if (
                _git_metadata_directory_identity(current) != identity
                or _git_metadata_directory_identity(
                    os.fstat(descriptor)
                ) != identity
            ):
                raise AuditInputError(
                    "local Git config changed during parsing"
                )
        for path, descriptor in (
            (git_dir, git_descriptor),
            (common_dir, common_descriptor),
        ):
            reopened = open_directory(path)
            if _git_metadata_directory_identity(os.fstat(reopened)) != (
                _git_metadata_directory_identity(os.fstat(descriptor))
            ):
                raise AuditInputError(
                    "local Git config changed during parsing"
                )
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
    if result.returncode != 0 or len(result.stdout) > MAX_LOCAL_CONFIG_BYTES:
        raise AuditInputError("local Git config could not be reviewed")
    forwarded: list[tuple[str, str]] = []
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        raw_key, separator, raw_value = record.partition(b"\n")
        try:
            key = raw_key.decode("ascii", "strict").lower()
        except UnicodeDecodeError as error:
            raise AuditInputError("local Git config key is invalid") from error
        if not separator or DANGEROUS_LOCAL_CONFIG.match(key):
            raise AuditInputError("local Git config is not inert")
        validator = FORWARDED_LOCAL_CONFIG.get(key)
        if validator is None:
            continue
        try:
            value = raw_value.decode("ascii", "strict")
        except UnicodeDecodeError as error:
            raise AuditInputError("local Git config value is invalid") from error
        if not validator.fullmatch(value):
            raise AuditInputError("local Git config value is not approved")
        forwarded.append((key, value))
    return _RepositoryConfigSnapshot(
        tuple(sorted(forwarded)), git_dir, common_dir
    )


def _repository_config(
    root: Path,
    config_runner: ConfigParserRunner = run_config_parser
) -> tuple[tuple[str, str], ...]:
    return _repository_config_snapshot(root, config_runner).values


def _config_stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns
    )


def _read_bounded_descriptor(descriptor: int, limit: int) -> bytes:
    payload = bytearray()
    while len(payload) <= limit:
        chunk = os.read(
            descriptor,
            min(READ_CHUNK_BYTES, limit + 1 - len(payload))
        )
        if not chunk:
            break
        payload.extend(chunk)
    if len(payload) > limit:
        raise AuditInputError(
            "local Git config is not a bounded regular file"
        )
    return bytes(payload)


class FindingCollector:
    def __init__(self) -> None:
        self._findings: list[Finding] = []
        self._seen: set[Finding] = set()
        self._rule_counts: dict[str, int] = {}
        self._truncated = False

    def add(self, finding: Finding) -> None:
        if finding in self._seen:
            return
        count = self._rule_counts.get(finding.rule_id, 0)
        if (
            len(self._findings) >= MAX_TOTAL_FINDINGS
            or count >= MAX_FINDINGS_PER_RULE
        ):
            self._truncated = True
            return
        self._seen.add(finding)
        self._findings.append(finding)
        self._rule_counts[finding.rule_id] = count + 1

    def extend(self, findings: Iterator[Finding] | Sequence[Finding]) -> None:
        for finding in findings:
            self.add(finding)

    def result(self) -> tuple[Finding, ...]:
        findings = list(self._findings)
        if self._truncated:
            findings.append(Finding(
                "scan.truncated", "incomplete-inspection", "", "",
                "finding limits were reached; publication remains blocked"
            ))
        return tuple(sorted(
            findings, key=lambda item: dataclasses.astuple(item)
        ))


def _has_control_characters(value: str) -> bool:
    return any(
        ord(character) < 0x20 or 0x7f <= ord(character) < 0xa0
        for character in value
    )


def _revalidate_refs(
    root: Path,
    refs: Sequence[tuple[str, str]],
    public_branches: Sequence[str],
    public_tag_patterns: Sequence[str],
    repository_config: Sequence[tuple[str, str]],
    runner: Runner
) -> None:
    selected = _select_public_ref_names(
        root, public_branches, public_tag_patterns, repository_config, runner
    )
    if selected != tuple(ref for ref, _ in refs):
        raise AuditInputError("selected public ref set changed")
    for ref, expected in refs:
        try:
            current = _git(
                root, "rev-parse", "--verify", f"{ref}^{{object}}",
                repository_config=repository_config, runner=runner
            ).decode("ascii", "strict").strip()
        except (AuditInputError, UnicodeDecodeError) as error:
            raise AuditInputError("selected public ref changed") from error
        if current != expected:
            raise AuditInputError("selected public ref changed")


def resolve_repository(
    root: Path,
    refs: Sequence[str],
    policy: Policy,
    runner: Runner = run_command,
    *,
    config_runner: ConfigParserRunner = run_config_parser
) -> RepositorySnapshot:
    root = root.resolve(strict=True)
    config_snapshot = _repository_config_snapshot(root, config_runner)
    repository_config = config_snapshot.values
    selected = _select_public_ref_names(
        root, policy.public_branches, policy.public_tag_patterns,
        repository_config, runner
    )
    if tuple(refs) != selected:
        raise AuditInputError("selected public ref set changed")
    top = Path(
        _git(
            root, "rev-parse", "--show-toplevel",
            repository_config=repository_config, runner=runner
        ).decode().strip()
    )
    if top != root:
        raise AuditInputError("repository root is not canonical")
    if _git(
        root, "rev-parse", "--is-shallow-repository",
        repository_config=repository_config, runner=runner
    ) != b"false\n":
        raise AuditInputError("shallow repository is not auditable")
    git_dir = Path(
        _git(
            root, "rev-parse", "--absolute-git-dir",
            repository_config=repository_config, runner=runner
        ).decode().strip()
    )
    common_dir = Path(
        _git(
            root, "rev-parse", "--path-format=absolute", "--git-common-dir",
            repository_config=repository_config, runner=runner
        ).decode().strip()
    )
    if (
        git_dir != config_snapshot.git_dir
        or common_dir != config_snapshot.common_dir
    ):
        raise AuditInputError("Git metadata changed during resolution")
    if (common_dir / "objects" / "info" / "alternates").exists():
        raise AuditInputError("Git object alternates are not auditable")
    grafts = common_dir / "info" / "grafts"
    if grafts.exists() and grafts.stat().st_size:
        raise AuditInputError("Git grafts are not auditable")
    replace = _git(
        root, "for-each-ref", "--format=%(refname)", "refs/replace",
        repository_config=repository_config, runner=runner
    )
    if replace.strip():
        raise AuditInputError("replace refs are not auditable")
    status = _git(
        root, "status", "--porcelain=v1", "--untracked-files=all",
        repository_config=repository_config, runner=runner
    )
    if status:
        raise AuditInputError("publication candidate is not clean")
    worktrees = _git(
        root, "worktree", "list", "--porcelain",
        repository_config=repository_config, runner=runner
    )
    current_worktree = b"worktree " + os.fsencode(root)
    worktree_records = tuple(
        line for line in worktrees.splitlines()
        if line.startswith(b"worktree ")
    )
    if worktree_records.count(current_worktree) != 1:
        raise AuditInputError("current worktree registration is not auditable")
    fsck = _git_result(
        root, "fsck", "--full", "--strict", "--no-dangling",
        repository_config=repository_config, runner=runner
    )
    if fsck.returncode != 0:
        raise AuditInputError("Git object database failed strict verification")
    resolved: list[tuple[str, str]] = []
    for ref in refs:
        object_id = _git(
            root, "rev-parse", "--verify", f"{ref}^{{object}}",
            repository_config=repository_config, runner=runner
        ).decode().strip()
        if not re.fullmatch(r"[0-9a-f]{40,64}", object_id):
            raise AuditInputError("public ref did not resolve exactly")
        resolved.append((ref, object_id))
    captured_ids = tuple(object_id for _, object_id in resolved)
    commits = tuple(
        line
        for line in _git(
            root, "rev-list", *captured_ids,
            repository_config=repository_config, runner=runner
        ).decode().splitlines()
        if line
    )
    objects: list[GitObject] = []
    for commit in commits:
        tree = _git(
            root, "ls-tree", "-rz", "-r", commit,
            repository_config=repository_config, runner=runner
        )
        for record in tree.split(b"\0"):
            if not record:
                continue
            metadata, separator, raw_path = record.partition(b"\t")
            fields = metadata.decode("ascii").split(" ")
            if (
                not separator
                or len(fields) != 3
                or fields[1] not in ("blob", "commit")
            ):
                raise AuditInputError("tree entry is malformed or unsupported")
            try:
                path = raw_path.decode("utf-8", "strict")
            except UnicodeDecodeError as error:
                raise AuditInputError(
                    "tree path encoding is not auditable"
                ) from error
            if _has_control_characters(path):
                raise AuditInputError(
                    "tree path contains control characters"
                )
            objects.append(GitObject(fields[0], fields[2], path, commit))
    current_config = _repository_config_snapshot(root, config_runner)
    if current_config != config_snapshot:
        raise AuditInputError("local Git config changed during resolution")
    _revalidate_refs(
        root, resolved, policy.public_branches, policy.public_tag_patterns,
        repository_config, runner
    )
    return RepositorySnapshot(
        root, git_dir, common_dir, tuple(resolved), policy.public_branches,
        policy.public_tag_patterns, commits, tuple(objects), repository_config
    )


def _select_public_ref_names(
    root: Path,
    public_branches: Sequence[str],
    public_tag_patterns: Sequence[str],
    repository_config: Sequence[tuple[str, str]],
    runner: Runner
) -> tuple[str, ...]:
    tags = _git(
        root, "for-each-ref", "--format=%(refname)", "refs/tags",
        repository_config=repository_config, runner=runner
    )
    patterns = tuple(re.compile(pattern) for pattern in public_tag_patterns)
    selected_tags = tuple(
        ref
        for ref in tags.decode("utf-8", "strict").splitlines()
        if any(pattern.fullmatch(ref) for pattern in patterns)
    )
    return (*public_branches, *selected_tags)


def select_public_refs(
    root: Path,
    policy: Policy,
    runner: Runner = run_command,
    *,
    config_runner: ConfigParserRunner = run_config_parser
) -> tuple[str, ...]:
    root = root.resolve(strict=True)
    repository_config = _repository_config(root, config_runner)
    return _select_public_ref_names(
        root, policy.public_branches, policy.public_tag_patterns,
        repository_config, runner
    )


def _excepted(
    policy: Policy,
    rule_id: str,
    path: str,
    data: bytes,
    *,
    agent_material: bool
) -> bool:
    digest = hashlib.sha256(data).hexdigest()
    exceptions = (*policy.path_exceptions, *policy.synthetic_exceptions)
    return any(
        item.rule_id == rule_id
        and item.path == path
        and item.sha256 == digest
        and item.agent_material is agent_material
        for item in exceptions
    )


def _path_rule(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    if any(
        normalized == item or normalized.startswith(item + "/")
        for item in FORBIDDEN_PATH_PARTS
    ):
        return "agent.material"
    if Path(normalized).suffix.lower() in ARCHIVE_SUFFIXES:
        return "opaque.or.private.file"
    return None


def _metadata_findings(
    snapshot: RepositorySnapshot,
    policy: Policy,
    runner: Runner
) -> Iterator[Finding]:
    approved = tuple(
        re.compile(pattern) for pattern in policy.public_email_patterns
    )
    formats = (
        ("author", "%ae"), ("committer", "%ce"),
    )
    for commit in snapshot.commits:
        raw_size = _git(
            snapshot.root, "cat-file", "-s", commit,
            repository_config=snapshot.git_config, runner=runner
        ).decode("ascii", "strict").strip()
        if not raw_size.isdigit():
            raise AuditInputError("reachable commit size is invalid")
        message_too_large = int(raw_size) > MAX_BLOB_BYTES
        for role, field in formats:
            value = _git(
                snapshot.root, "show", "-s", f"--format={field}", commit,
                repository_config=snapshot.git_config, runner=runner
            ).decode().strip()
            if not any(pattern.fullmatch(value) for pattern in approved):
                yield Finding(
                    "metadata.email", "private-metadata", "", commit,
                    f"{role} email is not an approved public identity"
                )
        if message_too_large:
            yield Finding(
                "metadata.too-large", "uninspected-metadata", "", commit,
                "commit object exceeds the message inspection limit"
            )
            continue
        message = _git(
            snapshot.root, "show", "-s", "--format=%B", commit,
            repository_config=snapshot.git_config, runner=runner
        )
        for rule_id, pattern in PRIVATE_PATTERNS:
            if pattern.search(message):
                yield Finding(
                    rule_id, "commit-message", "", commit,
                    "commit message matched a private-data rule; "
                    "matched value withheld"
                )
    for ref, selected_id in snapshot.refs:
        if not ref.startswith("refs/tags/"):
            continue
        object_id = selected_id
        seen: set[str] = set()
        while object_id not in seen:
            seen.add(object_id)
            object_type = _git(
                snapshot.root, "cat-file", "-t", object_id,
                repository_config=snapshot.git_config, runner=runner
            )
            if object_type != b"tag\n":
                break
            raw_size = _git(
                snapshot.root, "cat-file", "-s", object_id,
                repository_config=snapshot.git_config, runner=runner
            ).decode("ascii", "strict").strip()
            if not raw_size.isdigit() or int(raw_size) > MAX_BLOB_BYTES:
                yield Finding(
                    "metadata.too-large", "uninspected-metadata", ref,
                    object_id, "annotated tag exceeds the inspection limit"
                )
                break
            raw = _git(
                snapshot.root, "cat-file", "tag", object_id,
                repository_config=snapshot.git_config, runner=runner
            )
            headers, separator, message = raw.partition(b"\n\n")
            if not separator:
                raise AuditInputError("annotated tag object is malformed")
            target = b""
            tagger = b""
            for line in headers.splitlines():
                if line.startswith(b"object "):
                    target = line.removeprefix(b"object ")
                elif line.startswith(b"tagger "):
                    tagger = line.removeprefix(b"tagger ")
            email_match = re.search(rb"<([^<>\r\n]+)>", tagger)
            decoded_email = (
                email_match.group(1).decode("utf-8", "replace")
                if email_match else ""
            )
            if not any(pattern.fullmatch(decoded_email) for pattern in approved):
                yield Finding(
                    "metadata.email", "tag-metadata", ref, object_id,
                    "annotated tag email is not an approved public identity"
                )
            for rule_id, pattern in PRIVATE_PATTERNS:
                if pattern.search(message):
                    yield Finding(
                        rule_id, "tag-message", ref, object_id,
                        "annotated tag message matched a private-data rule; "
                        "matched value withheld"
                    )
            try:
                next_id = target.decode("ascii", "strict")
            except UnicodeDecodeError as error:
                raise AuditInputError("annotated tag target is invalid") from error
            if not re.fullmatch(r"[0-9a-f]{40,64}", next_id):
                raise AuditInputError("annotated tag target is invalid")
            object_id = next_id


def _submodule_findings(
    snapshot: RepositorySnapshot,
    entry: GitObject,
    runner: Runner
) -> Iterator[Finding]:
    if entry.path != ".gitmodules":
        return
    environment = git_environment()
    environment.pop("GIT_CONFIG")
    result = runner(
        _git_command(snapshot.root, (
            "config", "--blob", f"{entry.commit}:.gitmodules",
            "--no-includes", "--get-regexp", r"^submodule\..*\.url$"
        ), snapshot.git_config),
        None,
        environment
    )
    if result.returncode not in (0, 1):
        yield Finding(
            "submodule.config", "tracked-content", entry.path, entry.commit,
            "submodule configuration could not be parsed"
        )
        return
    try:
        lines = result.stdout.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError:
        yield Finding(
            "submodule.config", "tracked-content", entry.path, entry.commit,
            "submodule configuration could not be parsed"
        )
        return
    for line in lines:
        _, separator, url = line.partition(" ")
        if (
            not separator
            or not re.fullmatch(
                r"https://github\.com/[A-Za-z0-9_.-]+/"
                r"[A-Za-z0-9_.-]+(?:\.git)?",
                url
            )
        ):
            yield Finding(
                "submodule.private-url", "tracked-content", entry.path,
                entry.commit,
                "submodule URL is not an approved public GitHub HTTPS URL"
            )


def _content_identity_findings(
    data: bytes,
    path: str,
    object_id: str,
    policy: Policy
) -> Iterator[Finding]:
    approved_emails = tuple(
        re.compile(pattern) for pattern in policy.public_email_patterns
    )
    for match in EMAIL_PATTERN.finditer(data):
        value = match.group().decode("ascii")
        domain = value.rsplit("@", 1)[1].lower()
        if (
            domain in {"example.com", "example.net", "example.org"}
            or domain.endswith((".example", ".test", ".invalid"))
            or any(pattern.fullmatch(value) for pattern in approved_emails)
        ):
            continue
        if _excepted(
            policy, "private.email", path, data, agent_material=False
        ):
            break
        yield Finding(
            "private.email", "content-identity", path, object_id,
            "content contains an unapproved email address; value withheld"
        )
        break
    for match in IPV4_PATTERN.finditer(data):
        try:
            address = ipaddress.ip_address(match.group().decode("ascii"))
        except ValueError:
            continue
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_unspecified
        ):
            continue
        if _excepted(
            policy, "private.ip", path, data, agent_material=False
        ):
            break
        yield Finding(
            "private.ip", "content-identity", path, object_id,
            "content contains a public IP address; value withheld"
        )
        break
    for match in HOST_ASSIGNMENT_PATTERN.finditer(data):
        host = match.group(1).decode("ascii").lower().rstrip(".")
        if (
            host in PUBLIC_HOSTS
            or host.endswith((
                ".example", ".example.com", ".example.net", ".example.org",
                ".test", ".invalid"
            ))
        ):
            continue
        if _excepted(
            policy, "private.hostname", path, data, agent_material=False
        ):
            break
        yield Finding(
            "private.hostname", "content-identity", path, object_id,
            "content contains an unapproved configured hostname; value withheld"
        )
        break


def _content_findings(
    data: bytes,
    path: str,
    object_id: str,
    policy: Policy
) -> Iterator[Finding]:
    rule = _path_rule(path)
    if (
        rule
        and not _excepted(
            policy, rule, path, data, agent_material=rule == "agent.material"
        )
    ):
        yield Finding(
            rule, "tracked-path", path, object_id,
            "tracked path is not public-safe"
        )
    try:
        data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        if not _excepted(
            policy, "content.unsupported-encoding", path, data,
            agent_material=False
        ):
            yield Finding(
                "content.unsupported-encoding", "uninspected-content",
                path, object_id,
                "non-UTF-8 content requires explicit format review"
            )
    yield from _content_identity_findings(data, path, object_id, policy)
    for rule_id, pattern in PRIVATE_PATTERNS:
        if (
            pattern.search(data)
            and not _excepted(
                policy, rule_id, path, data, agent_material=False
            )
        ):
            yield Finding(
                rule_id, "content", path, object_id,
                "content matched a private-data rule; matched value withheld"
            )


class _LFSObjectMissing(RuntimeError):
    pass


class _LFSObjectInvalid(RuntimeError):
    pass


def _lfs_stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns
    )


def _read_lfs_payload(
    common_dir: Path,
    digest: str,
    expected_size: int
) -> bytes:
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
    ):
        raise _LFSObjectInvalid("no-follow descriptor access is unavailable")
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | close_on_exec
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | close_on_exec
    descriptors: list[int] = []
    try:
        try:
            descriptor = os.open(os.fspath(common_dir), directory_flags)
            descriptors.append(descriptor)
            for component in (
                "lfs", "objects", digest[:2], digest[2:4]
            ):
                descriptor = os.open(
                    component, directory_flags, dir_fd=descriptor
                )
                descriptors.append(descriptor)
            file_descriptor = os.open(
                digest, file_flags, dir_fd=descriptor
            )
            descriptors.append(file_descriptor)
        except FileNotFoundError as error:
            raise _LFSObjectMissing("Git LFS object is unavailable") from error
        except OSError as error:
            if error.errno == errno.ENOENT:
                raise _LFSObjectMissing(
                    "Git LFS object is unavailable"
                ) from error
            raise _LFSObjectInvalid(
                "Git LFS object path is unsafe"
            ) from error
        before = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size != expected_size
            or expected_size > MAX_BLOB_BYTES
        ):
            raise _LFSObjectInvalid("Git LFS object size or type is invalid")
        hasher = hashlib.sha256()
        payload = bytearray()
        while True:
            chunk = os.read(file_descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            if len(payload) + len(chunk) > MAX_BLOB_BYTES:
                raise _LFSObjectInvalid("Git LFS object exceeded its bound")
            payload.extend(chunk)
            hasher.update(chunk)
        after = os.fstat(file_descriptor)
        if (
            _lfs_stat_identity(before) != _lfs_stat_identity(after)
            or len(payload) != expected_size
            or hasher.hexdigest() != digest
        ):
            raise _LFSObjectInvalid("Git LFS object identity changed")
        return bytes(payload)
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _lfs_findings(
    snapshot: RepositorySnapshot,
    policy: Policy,
    entry: GitObject,
    pointer: bytes
) -> Iterator[Finding]:
    match = re.fullmatch(
        rb"version https://git-lfs\.github\.com/spec/v1\n"
        rb"oid sha256:([0-9a-f]{64})\nsize ([0-9]+)\n",
        pointer,
    )
    if not match:
        yield Finding(
            "lfs.pointer", "unverified-object", entry.path, entry.object_id,
            "Git LFS pointer is malformed"
        )
        return
    digest = match.group(1).decode("ascii")
    size = int(match.group(2))
    if size > MAX_BLOB_BYTES:
        yield Finding(
            "blob.too-large", "uninspected-content", entry.path, digest,
            "Git LFS object exceeds the 10 MiB inspection limit"
        )
        return
    try:
        data = _read_lfs_payload(snapshot.common_dir, digest, size)
    except _LFSObjectMissing:
        yield Finding(
            "lfs.missing-object", "unverified-object", entry.path, digest,
            "Git LFS object is unavailable"
        )
        return
    except _LFSObjectInvalid:
        yield Finding(
            "lfs.invalid-object", "unverified-object", entry.path, digest,
            "Git LFS object identity or size is invalid"
        )
        return
    if not _excepted(
        policy, "lfs.object", entry.path, data, agent_material=False
    ):
        yield Finding(
            "lfs.review-required", "unverified-object", entry.path, digest,
            "Git LFS object requires an exact content-bound review exception"
        )
        return
    yield from _content_findings(data, entry.path, digest, policy)


def scan_git(
    snapshot: RepositorySnapshot,
    policy: Policy,
    runner: Runner = run_command,
    *,
    config_runner: ConfigParserRunner = run_config_parser
) -> tuple[Finding, ...]:
    if (
        policy.public_branches != snapshot.public_branches
        or policy.public_tag_patterns != snapshot.public_tag_patterns
    ):
        raise AuditInputError(
            "policy selection contract differs from repository snapshot"
        )
    if _repository_config(snapshot.root, config_runner) != snapshot.git_config:
        raise AuditInputError("local Git config changed after resolution")
    _revalidate_refs(
        snapshot.root, snapshot.refs, snapshot.public_branches,
        snapshot.public_tag_patterns, snapshot.git_config, runner
    )
    findings = FindingCollector()
    findings.extend(_metadata_findings(snapshot, policy, runner))
    seen: set[tuple[str, str, str]] = set()
    for entry in snapshot.objects:
        path = entry.path
        object_id = entry.object_id
        identity = (entry.mode, object_id, path)
        if not path or identity in seen:
            continue
        seen.add(identity)
        if entry.mode == "160000":
            findings.add(Finding(
                "submodule.unresolved", "tracked-mode", path, entry.commit,
                "submodule requires exact URL and object review"
            ))
            continue
        type_result = _git_result(
            snapshot.root, "cat-file", "-t", object_id,
            repository_config=snapshot.git_config, runner=runner
        )
        if type_result.returncode != 0:
            findings.add(Finding(
                "repository.missing-object", "git-integrity", path, object_id,
                "reachable object is unavailable"
            ))
            continue
        if type_result.stdout != b"blob\n":
            continue
        raw_size = _git(
            snapshot.root, "cat-file", "-s", object_id,
            repository_config=snapshot.git_config, runner=runner
        ).decode("ascii", "strict").strip()
        if not raw_size.isdigit():
            raise AuditInputError("reachable blob size is invalid")
        size = int(raw_size)
        if size > MAX_BLOB_BYTES:
            findings.add(Finding(
                "blob.too-large", "uninspected-content", path, object_id,
                "blob exceeds the 10 MiB inspection limit"
            ))
            continue
        data = _git(
            snapshot.root, "cat-file", "blob", object_id,
            repository_config=snapshot.git_config, runner=runner
        )
        if len(data) != size:
            raise AuditInputError("reachable blob changed during inspection")
        findings.extend(_submodule_findings(snapshot, entry, runner))
        findings.extend(_content_findings(data, path, object_id, policy))
        if entry.mode == "120000":
            try:
                target = data.decode("utf-8", "strict")
            except UnicodeDecodeError:
                continue
            normalized_target = target.replace("\\", "/")
            if (
                normalized_target.startswith("/")
                or re.match(r"^[A-Za-z]:/", normalized_target)
                or ".." in Path(normalized_target).parts
            ):
                findings.add(Finding(
                    "symlink.escape", "tracked-mode", path, object_id,
                    "symlink target is absolute or escapes its repository directory"
                ))
        if data.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
            findings.extend(_lfs_findings(snapshot, policy, entry, data))
    if _repository_config(snapshot.root, config_runner) != snapshot.git_config:
        raise AuditInputError("local Git config changed during inspection")
    _revalidate_refs(
        snapshot.root, snapshot.refs, snapshot.public_branches,
        snapshot.public_tag_patterns, snapshot.git_config, runner
    )
    return findings.result()


def _render_field(value: str) -> str:
    rendered: list[str] = []
    for character in value:
        codepoint = ord(character)
        if (
            character == "\\"
            or codepoint < 0x20
            or 0x7f <= codepoint < 0xa0
        ):
            rendered.append(f"\\x{codepoint:02x}")
        else:
            rendered.append(character)
    return "".join(rendered)


def render_findings(findings: Sequence[Finding]) -> str:
    return "\n".join(
        "\t".join(_render_field(field) for field in (
            item.rule_id, item.classification, item.path,
            item.location, item.message
        ))
        for item in findings
    )


class ToolError(RuntimeError):
    pass


MAX_GITLEAKS_REPORT_BYTES = 8 * 1024 * 1024
MAX_GITLEAKS_REPORT_ITEMS = 10_000
MAX_GITLEAKS_RULE_BYTES = 256
MAX_GITLEAKS_PATH_BYTES = 4096
MAX_GITLEAKS_REDACTED_BYTES = 64 * 1024
GITLEAKS_REDACTION_MARKER = "REDACTED"
GITLEAKS_DEFAULT_CONFIG = b"[extend]\nuseDefault = true\n"
GITLEAKS_DEFAULT_CONFIG_SHA256 = (
    "27630a96d6c55755cc37620f3933d5cab"
    "94b1eb78a726a32e11212972525d76e"
)


@dataclass(frozen=True)
class _GitleaksMatch:
    rule_id: str
    path: str
    location: str
    mode: str


def gitleaks_environment(home: Path) -> dict[str, str]:
    environment = git_environment()
    private_home = os.fspath(home)
    environment.update({
        "HOME": private_home,
        "USERPROFILE": private_home,
        "XDG_CONFIG_HOME": private_home,
        "TMPDIR": private_home,
        "TMP": private_home,
        "TEMP": private_home,
    })
    return {
        name: value
        for name, value in environment.items()
        if not name.startswith("GITLEAKS_")
    }


def _new_gitleaks_workspace() -> Path:
    try:
        workspace = Path(tempfile.mkdtemp(
            prefix="public-repository-safety-"
        )).resolve(strict=True)
        os.chmod(workspace, 0o700)
    except OSError:
        raise ToolError(
            "private gitleaks workspace could not be created"
        ) from None
    return workspace


def _cleanup_gitleaks_workspace(workspace: Path) -> None:
    try:
        shutil.rmtree(workspace)
    except OSError:
        raise ToolError(
            "private gitleaks workspace cleanup failed"
        ) from None


def _tool_version(
    name: str,
    runner: Runner,
    cwd: Path,
    environment: Mapping[str, str]
) -> str:
    try:
        result = runner((name, "version"), cwd, environment)
    except OSError:
        raise ToolError(f"{name} is unavailable") from None
    if result.returncode != 0:
        raise ToolError(f"{name} is unavailable")
    return result.stdout.decode(
        "utf-8", "replace"
    ).strip().removeprefix("v")


def tool_version(name: str, runner: Runner = run_command) -> str:
    workspace = _new_gitleaks_workspace()
    try:
        return _tool_version(
            name, runner, workspace, gitleaks_environment(workspace)
        )
    finally:
        _cleanup_gitleaks_workspace(workspace)


def _write_private_gitleaks_file(path: Path, payload: bytes) -> None:
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | close_on_exec | no_follow
    try:
        descriptor = os.open(os.fspath(path), flags, 0o600)
    except OSError:
        raise ToolError("private gitleaks control file is unavailable") from None
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ToolError("private gitleaks control file is invalid")
            view = view[written:]
        before_close = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before_close.st_mode)
            or before_close.st_size != len(payload)
        ):
            raise ToolError("private gitleaks control file is invalid")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    try:
        os.chmod(path, 0o600)
    except OSError:
        raise ToolError("private gitleaks control file is invalid") from None


def _write_empty_gitleaks_ignore(path: Path) -> None:
    _write_private_gitleaks_file(path, b"")


def _write_gitleaks_default_config(path: Path) -> None:
    if hash_bytes(
        GITLEAKS_DEFAULT_CONFIG
    ) != GITLEAKS_DEFAULT_CONFIG_SHA256:
        raise ToolError("trusted gitleaks config identity is invalid")
    _write_private_gitleaks_file(path, GITLEAKS_DEFAULT_CONFIG)


def _read_gitleaks_report(path: Path, workspace: Path) -> bytes:
    if (
        path.parent != workspace
        or not path.name.startswith("gitleaks-")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        raise ToolError("gitleaks report path is invalid")
    flags = (
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(os.fspath(path), flags)
    except OSError:
        raise ToolError("gitleaks report is unavailable") from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > MAX_GITLEAKS_REPORT_BYTES
        ):
            raise ToolError("gitleaks report is invalid")
        try:
            payload = _read_bounded_descriptor(
                descriptor, MAX_GITLEAKS_REPORT_BYTES
            )
        except AuditInputError:
            raise ToolError("gitleaks report is invalid") from None
        after = os.fstat(descriptor)
        if (
            _config_stat_identity(before) != _config_stat_identity(after)
            or len(payload) != before.st_size
        ):
            raise ToolError("gitleaks report changed during inspection")
        return payload
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _gitleaks_text(
    item: Mapping[str, object],
    field: str,
    maximum_bytes: int,
    *,
    allow_empty: bool = False,
    allow_controls: bool = False
) -> str:
    if field not in item or not isinstance(item[field], str):
        raise ToolError("gitleaks report has invalid fields")
    value = item[field]
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        raise ToolError("gitleaks report has invalid fields") from None
    if (
        (not value and not allow_empty)
        or len(encoded) > maximum_bytes
        or (not allow_controls and _has_control_characters(value))
    ):
        raise ToolError("gitleaks report has invalid fields")
    return value


def _gitleaks_path(
    item: Mapping[str, object],
    mode: str,
    snapshot: RepositorySnapshot
) -> str:
    root_bytes = len(
        os.fspath(snapshot.root).encode("utf-8", "strict")
    )
    reported = _gitleaks_text(
        item, "File", root_bytes + MAX_GITLEAKS_PATH_BYTES + 1
    )
    if mode == "dir":
        candidate = Path(reported)
        reported_parts = reported.split("/")
        if (
            not candidate.is_absolute()
            or not reported.startswith("/")
            or any(
                part in ("", ".", "..")
                for part in reported_parts[1:]
            )
        ):
            raise ToolError("gitleaks report has invalid path")
        try:
            path = candidate.relative_to(snapshot.root).as_posix()
        except ValueError:
            raise ToolError("gitleaks report has invalid path") from None
    else:
        path = reported
    parts = path.split("/")
    if (
        path.startswith(("/", "\\"))
        or "\\" in path
        or re.match(r"^[A-Za-z]:", path)
        or any(part in ("", ".", "..") for part in parts)
    ):
        raise ToolError("gitleaks report has invalid path")
    return path


def _gitleaks_match(
    item: Mapping[str, object],
    mode: str,
    snapshot: RepositorySnapshot,
    objects: Mapping[tuple[str, str], GitObject]
) -> _GitleaksMatch:
    rule_id = _gitleaks_text(
        item, "RuleID", MAX_GITLEAKS_RULE_BYTES
    )
    if RULE_ID_PATTERN.fullmatch(rule_id) is None:
        raise ToolError("gitleaks report has invalid fields")
    path = _gitleaks_path(item, mode, snapshot)
    commit = _gitleaks_text(
        item, "Commit", 64, allow_empty=True
    )
    secret = _gitleaks_text(
        item, "Secret", MAX_GITLEAKS_REDACTED_BYTES,
        allow_controls=True
    )
    match = _gitleaks_text(
        item, "Match", MAX_GITLEAKS_REDACTED_BYTES,
        allow_controls=True
    )
    if (
        secret != GITLEAKS_REDACTION_MARKER
        or GITLEAKS_REDACTION_MARKER not in match
    ):
        raise ToolError("gitleaks report is not fully redacted")
    if mode == "git":
        if (
            not re.fullmatch(r"[0-9a-f]{40,64}", commit)
            or commit not in snapshot.commits
            or (commit, path) not in objects
        ):
            raise ToolError(
                "gitleaks history provenance is invalid"
            )
        location = commit
    elif mode == "dir":
        if commit:
            raise ToolError("gitleaks tree provenance is invalid")
        location = "working-tree"
    else:
        raise ToolError("gitleaks report mode is invalid")
    return _GitleaksMatch(
        f"gitleaks.{rule_id}", path, location, mode
    )


def _decode_gitleaks_report(
    payload: bytes,
    mode: str,
    returncode: int,
    snapshot: RepositorySnapshot,
    objects: Mapping[tuple[str, str], GitObject]
) -> tuple[_GitleaksMatch, ...]:
    try:
        decoded = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_object_pairs
        )
    except (
        UnicodeError, json.JSONDecodeError, PolicyError
    ):
        raise ToolError(f"gitleaks {mode} report is unreadable") from None
    if (
        not isinstance(decoded, list)
        or len(decoded) > MAX_GITLEAKS_REPORT_ITEMS
        or not all(isinstance(item, dict) for item in decoded)
    ):
        raise ToolError(f"gitleaks {mode} report has invalid shape")
    if (
        returncode not in (0, 1)
        or (returncode == 0 and decoded)
        or (returncode == 1 and not decoded)
    ):
        raise ToolError(
            f"gitleaks {mode} exit and report disagree"
        )
    return tuple(
        _gitleaks_match(item, mode, snapshot, objects)
        for item in decoded
    )


def _read_repository_file(root: Path, path: str) -> bytes:
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
    ):
        raise ToolError(
            "bounded repository file access is unavailable"
        )
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | close_on_exec
    )
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | close_on_exec
    descriptors: list[int] = []
    try:
        try:
            descriptor = os.open(os.fspath(root), directory_flags)
            descriptors.append(descriptor)
            parts = path.split("/")
            for component in parts[:-1]:
                descriptor = os.open(
                    component, directory_flags, dir_fd=descriptor
                )
                descriptors.append(descriptor)
            file_descriptor = os.open(
                parts[-1], file_flags, dir_fd=descriptor
            )
            descriptors.append(file_descriptor)
        except OSError:
            raise ToolError(
                "gitleaks finding content could not be verified"
            ) from None
        before = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > MAX_BLOB_BYTES
        ):
            raise ToolError(
                "gitleaks finding content could not be verified"
            )
        try:
            payload = _read_bounded_descriptor(
                file_descriptor, MAX_BLOB_BYTES
            )
        except AuditInputError:
            raise ToolError(
                "gitleaks finding content could not be verified"
            ) from None
        after = os.fstat(file_descriptor)
        if (
            _config_stat_identity(before) != _config_stat_identity(after)
            or len(payload) != before.st_size
        ):
            raise ToolError(
                "gitleaks finding content could not be verified"
            )
        return payload
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_gitleaks_content(
    snapshot: RepositorySnapshot,
    match: _GitleaksMatch,
    objects: Mapping[tuple[str, str], GitObject]
) -> bytes:
    if match.mode == "dir":
        return _read_repository_file(snapshot.root, match.path)
    entry = objects[(match.location, match.path)]
    try:
        raw_size = _git(
            snapshot.root, "cat-file", "-s", entry.object_id,
            repository_config=snapshot.git_config
        ).decode("ascii", "strict").strip()
        if (
            not raw_size.isdigit()
            or int(raw_size) > MAX_BLOB_BYTES
        ):
            raise ToolError(
                "gitleaks finding content could not be verified"
            )
        payload = _git(
            snapshot.root, "cat-file", "blob", entry.object_id,
            repository_config=snapshot.git_config
        )
        if len(payload) != int(raw_size):
            raise ToolError(
                "gitleaks finding content could not be verified"
            )
        return payload
    except (
        AuditInputError, UnicodeError, KeyError
    ):
        raise ToolError(
            "gitleaks finding content could not be verified"
        ) from None


def _revalidate_gitleaks_candidate(
    snapshot: RepositorySnapshot,
    policy: Policy
) -> None:
    if (
        policy.public_branches != snapshot.public_branches
        or policy.public_tag_patterns != snapshot.public_tag_patterns
    ):
        raise ToolError(
            "policy selection contract differs from repository snapshot"
        )
    try:
        if _repository_config(snapshot.root) != snapshot.git_config:
            raise AuditInputError(
                "local Git config changed after resolution"
            )
        _revalidate_refs(
            snapshot.root, snapshot.refs, snapshot.public_branches,
            snapshot.public_tag_patterns, snapshot.git_config,
            run_command
        )
        status = _git(
            snapshot.root, "status", "--porcelain=v1",
            "--untracked-files=all",
            repository_config=snapshot.git_config
        )
        if status:
            raise AuditInputError(
                "publication candidate is not clean"
            )
    except (AuditInputError, OSError, UnicodeError):
        raise ToolError(
            "repository changed during gitleaks inspection"
        ) from None


def scan_gitleaks(
    snapshot: RepositorySnapshot,
    policy: Policy,
    runner: Runner = run_command
) -> tuple[Finding, ...]:
    _revalidate_gitleaks_candidate(snapshot, policy)
    objects = {
        (entry.commit, entry.path): entry
        for entry in snapshot.objects
        if entry.mode != "160000"
    }
    temporary_root = _new_gitleaks_workspace()
    try:
        environment = gitleaks_environment(temporary_root)
        version = _tool_version(
            "gitleaks", runner, temporary_root, environment
        )
        if version != policy.gitleaks_version:
            raise ToolError(
                f"gitleaks {policy.gitleaks_version} is required"
            )
        empty_ignore = temporary_root / "empty-ignore"
        _write_empty_gitleaks_ignore(empty_ignore)
        default_config = temporary_root / "default-config.toml"
        _write_gitleaks_default_config(default_config)
        commands = (
            ("git", "--log-opts=--all"),
            ("dir", None),
        )
        matches: list[_GitleaksMatch] = []
        for index, (mode, log_options) in enumerate(commands):
            report = temporary_root / f"gitleaks-{index}.json"
            argv = [
                "gitleaks", mode, "--no-banner", "--redact=100",
                "--ignore-gitleaks-allow",
                "--config", os.fspath(default_config),
                "--gitleaks-ignore-path", os.fspath(empty_ignore),
                "--report-format", "json",
                "--report-path", os.fspath(report)
            ]
            if log_options is not None:
                argv.append(log_options)
            argv.append(os.fspath(snapshot.root))
            try:
                result = runner(
                    tuple(argv), temporary_root, environment
                )
            except OSError:
                raise ToolError(
                    f"gitleaks {mode} scan was incomplete"
                ) from None
            payload = _read_gitleaks_report(
                report, temporary_root
            )
            matches.extend(_decode_gitleaks_report(
                payload, mode, result.returncode, snapshot, objects
            ))
        findings = FindingCollector()
        for match in matches:
            content = _read_gitleaks_content(
                snapshot, match, objects
            )
            if not _excepted(
                policy, match.rule_id, match.path, content,
                agent_material=False
            ):
                findings.add(Finding(
                    match.rule_id, "secret-scanner",
                    match.path, match.location,
                    "secret scanner matched content; matched value withheld"
                ))
        result = findings.result()
        _revalidate_gitleaks_candidate(snapshot, policy)
        return result
    finally:
        _cleanup_gitleaks_workspace(temporary_root)


class ApprovalError(RuntimeError):
    pass


MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 256 * 1024
MAX_APPROVAL_TRANSACTION_BYTES = 4 * 1024
PRIVATE_STATE_NAME = "public-repository-safety"
APPROVAL_INTENT_NAME = "approval.intent"
APPROVAL_COMMITTED_NAME = "approval.committed"
LOCAL_CHECK_NAMES = frozenset({"git", "gitleaks"})
PUBLICATION_CHECK_NAMES = frozenset({
    "git", "gitleaks", "github"
})
REPORT_KEYS = {
    "schema_version", "repository", "intended_remote",
    "intended_visibility", "refs", "tree_ids", "scanner_sha256",
    "policy_sha256", "exception_sha256", "manual_documents", "tools",
    "audit_scope", "checks", "finding_count", "findings", "result"
}
RECEIPT_KEYS = {
    "schema_version", "transaction_id", "report_digest", "approval_id",
    "repository", "intended_remote", "intended_visibility", "refs",
    "tree_ids", "scanner_sha256", "policy_sha256", "exception_sha256",
    "manual_documents", "tools", "audit_scope", "checks",
    "finding_count", "result"
}
APPROVAL_TRANSACTION_KEYS = {
    "schema_version", "transaction_id", "report_digest", "approval_id",
    "receipt_sha256"
}
ABSOLUTE_PATH_TEXT = re.compile(
    r"(?:^|[\s`\"'(=])(?:/(?!/)[^\s`\"')]+|"
    r"[A-Za-z]:[\\/][^\s`\"')]+)"
)


def canonical_json(value: object) -> bytes:
    rendered = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":")
    )
    return (rendered + "\n").encode("ascii")


def private_state_dir(root: Path) -> Path:
    try:
        canonical_root = root.resolve(strict=True)
        config_snapshot = _repository_config_snapshot(canonical_root)
        repository_config = config_snapshot.values
        top = Path(_git(
            canonical_root,
            "rev-parse",
            "--show-toplevel",
            repository_config=repository_config
        ).decode("utf-8", "strict").strip())
        git_dir = Path(_git(
            canonical_root,
            "rev-parse",
            "--absolute-git-dir",
            repository_config=repository_config
        ).decode("utf-8", "strict").strip())
        common_dir = Path(_git(
            canonical_root,
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
            repository_config=repository_config
        ).decode("utf-8", "strict").strip())
        if (
            top != canonical_root
            or git_dir != config_snapshot.git_dir
            or common_dir != config_snapshot.common_dir
            or not common_dir.is_absolute()
        ):
            raise AuditInputError(
                "private Git state location is not canonical"
            )
        return common_dir / PRIVATE_STATE_NAME
    except (OSError, UnicodeError):
        raise AuditInputError(
            "private Git state location is unavailable"
        ) from None


def _private_state_descriptor(
    root: Path,
    *,
    create: bool
) -> tuple[int, Path]:
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
    ):
        raise AuditInputError("private state access is unavailable")
    state = private_state_dir(root)
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    common_descriptor = -1
    state_descriptor = -1
    try:
        common_descriptor = os.open(os.fspath(state.parent), flags)
        if create:
            try:
                os.mkdir(state.name, 0o700, dir_fd=common_descriptor)
            except FileExistsError:
                pass
        state_descriptor = os.open(
            state.name, flags, dir_fd=common_descriptor
        )
        info = os.fstat(state_descriptor)
        current_uid = getattr(os, "geteuid", lambda: info.st_uid)()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != current_uid
        ):
            raise AuditInputError("private state directory is unsafe")
        if create:
            os.fchmod(state_descriptor, 0o700)
            info = os.fstat(state_descriptor)
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise AuditInputError(
                "private state directory permissions are unsafe"
            )
        return state_descriptor, state
    except AuditInputError:
        if state_descriptor >= 0:
            os.close(state_descriptor)
        raise
    except OSError:
        if state_descriptor >= 0:
            os.close(state_descriptor)
        raise AuditInputError(
            "private state directory is unavailable or unsafe"
        ) from None
    finally:
        if common_descriptor >= 0:
            os.close(common_descriptor)


def _read_private_artifact(
    state_descriptor: int,
    name: str,
    limit: int
) -> bytes:
    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(
            name, flags, dir_fd=state_descriptor
        )
        before = os.fstat(descriptor)
        current_uid = getattr(os, "geteuid", lambda: before.st_uid)()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != current_uid
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > limit
        ):
            raise AuditInputError("private artifact is unsafe")
        try:
            payload = _read_bounded_descriptor(descriptor, limit)
        except AuditInputError:
            raise AuditInputError("private artifact is unsafe") from None
        after = os.fstat(descriptor)
        if (
            _config_stat_identity(before) != _config_stat_identity(after)
            or len(payload) != before.st_size
        ):
            raise AuditInputError(
                "private artifact changed during inspection"
            )
        return payload
    except OSError:
        raise AuditInputError(
            "private artifact is unavailable or unsafe"
        ) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _atomic_write_private(
    state_descriptor: int,
    name: str,
    payload: bytes,
    error_type: type[RuntimeError],
    description: str
) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    temporary = ""
    descriptor = -1
    replaced = False
    try:
        for _ in range(16):
            candidate = f".{name}.{secrets.token_hex(16)}"
            try:
                descriptor = os.open(
                    candidate,
                    flags,
                    0o600,
                    dir_fd=state_descriptor
                )
                temporary = candidate
                break
            except FileExistsError:
                continue
        if descriptor < 0:
            raise OSError(errno.EEXIST, "temporary file unavailable")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(errno.EIO, "short write")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != len(payload)
        ):
            raise OSError(errno.EIO, "private artifact is invalid")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary,
            name,
            src_dir_fd=state_descriptor,
            dst_dir_fd=state_descriptor
        )
        temporary = ""
        replaced = True
        os.fsync(state_descriptor)
    except OSError:
        if replaced:
            try:
                os.unlink(name, dir_fd=state_descriptor)
            except OSError:
                pass
        raise error_type(
            f"private {description} could not be written atomically"
        ) from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary:
            try:
                os.unlink(temporary, dir_fd=state_descriptor)
            except OSError:
                pass


def _prepare_private_replacement(
    state_descriptor: int,
    name: str,
    payload: bytes,
    error_type: type[RuntimeError],
    description: str
) -> str:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    temporary = ""
    descriptor = -1
    try:
        for _ in range(16):
            candidate = f".{name}.{secrets.token_hex(16)}"
            try:
                descriptor = os.open(
                    candidate,
                    flags,
                    0o600,
                    dir_fd=state_descriptor
                )
                temporary = candidate
                break
            except FileExistsError:
                continue
        if descriptor < 0:
            raise OSError(errno.EEXIST, "temporary file unavailable")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(errno.EIO, "short write")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != len(payload)
        ):
            raise OSError(errno.EIO, "private artifact is invalid")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.fsync(state_descriptor)
        return temporary
    except OSError:
        if temporary:
            try:
                os.unlink(temporary, dir_fd=state_descriptor)
            except OSError:
                pass
        raise error_type(
            f"private {description} could not be prepared atomically"
        ) from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_absolute_regular_file(
    path: Path,
    limit: int,
    context: str
) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    try:
        canonical = path.resolve(strict=True)
        descriptor = os.open(os.fspath(canonical), flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > limit
        ):
            raise AuditInputError(f"{context} is unsafe")
        try:
            payload = _read_bounded_descriptor(descriptor, limit)
        except AuditInputError:
            raise AuditInputError(f"{context} is unsafe") from None
        after = os.fstat(descriptor)
        if (
            _config_stat_identity(before) != _config_stat_identity(after)
            or len(payload) != before.st_size
        ):
            raise AuditInputError(
                f"{context} changed during inspection"
            )
        return payload
    except OSError:
        raise AuditInputError(f"{context} is unavailable or unsafe") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _document_digests(root: Path, policy: Policy) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in policy.manual_documents:
        try:
            payload = _read_repository_file(root, name)
        except ToolError:
            raise AuditInputError(
                f"manual document is missing or unsafe: {name}"
            ) from None
        result[name] = hash_bytes(payload)
    return result


def _actual_gitleaks_version(policy: Policy) -> str:
    try:
        version = tool_version("gitleaks")
    except ToolError:
        raise AuditInputError(
            "required gitleaks version is unavailable"
        ) from None
    if version != policy.gitleaks_version:
        raise AuditInputError(
            f"gitleaks {policy.gitleaks_version} is required"
        )
    return version


def _policy_bytes(root: Path, policy: Policy) -> bytes:
    path = root / ".public-repository-safety.json"
    try:
        payload = _read_repository_file(
            root, ".public-repository-safety.json"
        )
        current = load_policy(path)
        if current != policy:
            raise AuditInputError(
                "policy differs from the repository snapshot"
            )
        if _read_repository_file(
            root, ".public-repository-safety.json"
        ) != payload:
            raise AuditInputError(
                "policy changed during report generation"
            )
        return payload
    except ToolError:
        raise AuditInputError("policy is missing or unsafe") from None
    except PolicyError:
        raise AuditInputError("policy is invalid") from None


def _validate_report_candidate(
    snapshot: RepositorySnapshot,
    policy: Policy
) -> None:
    if (
        snapshot.root.resolve(strict=True) != snapshot.root
        or policy.public_branches != snapshot.public_branches
        or policy.public_tag_patterns != snapshot.public_tag_patterns
    ):
        raise AuditInputError(
            "report inputs differ from the repository snapshot"
        )
    if _repository_config(snapshot.root) != snapshot.git_config:
        raise AuditInputError("local Git config changed after resolution")
    _revalidate_refs(
        snapshot.root,
        snapshot.refs,
        snapshot.public_branches,
        snapshot.public_tag_patterns,
        snapshot.git_config,
        run_command
    )
    status = _git(
        snapshot.root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        repository_config=snapshot.git_config
    )
    if status:
        raise AuditInputError("publication candidate is not clean")


def _validated_checks(checks: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(checks, Mapping) or len(checks) > 64:
        raise AuditInputError("report checks are invalid")
    result: dict[str, str] = {}
    for name, value in checks.items():
        if (
            not isinstance(name, str)
            or RULE_ID_PATTERN.fullmatch(name) is None
            or value not in {"pass", "fail"}
        ):
            raise AuditInputError("report checks are invalid")
        result[name] = value
    return dict(sorted(result.items()))


def _publication_checks_pass(report: Mapping[str, object]) -> bool:
    checks = report.get("checks")
    return (
        report.get("result") == "pass"
        and isinstance(checks, Mapping)
        and frozenset(checks) == PUBLICATION_CHECK_NAMES
        and all(value == "pass" for value in checks.values())
    )


def _publication_report_eligible(
    report: Mapping[str, object],
) -> bool:
    return (
        report.get("audit_scope") == "publication"
        and _publication_checks_pass(report)
    )


def _finding_payload(finding: Finding) -> dict[str, str]:
    if not isinstance(finding, Finding):
        raise AuditInputError("report finding is invalid")
    values = dataclasses.asdict(finding)
    if (
        not all(isinstance(value, str) for value in values.values())
        or
        RULE_ID_PATTERN.fullmatch(finding.rule_id) is None
        or not re.fullmatch(
            r"[a-z0-9][a-z0-9._-]{1,79}", finding.classification
        )
        or any(
            not isinstance(value, str)
            or len(value.encode("utf-8")) > limit
            or _has_control_characters(value)
            for value, limit in (
                (finding.path, MAX_GITLEAKS_PATH_BYTES),
                (finding.location, MAX_GITLEAKS_PATH_BYTES),
                (finding.message, 1000),
            )
        )
    ):
        raise AuditInputError("report finding is invalid")
    normalized = finding.path.replace("\\", "/")
    if (
        normalized.startswith("/")
        or re.match(r"^[A-Za-z]:/", normalized)
        or ".." in Path(normalized).parts
        or any(
            ABSOLUTE_PATH_TEXT.search(value)
            or pattern.search(value.encode("utf-8"))
            for value in (
                finding.path, finding.location, finding.message
            )
            for _, pattern in PRIVATE_PATTERNS
        )
    ):
        raise AuditInputError(
            "report finding contains a private absolute path"
        )
    return values


def report_payload(
    snapshot: RepositorySnapshot,
    policy: Policy,
    findings: Sequence[Finding],
    checks: Mapping[str, str]
) -> dict[str, object]:
    _validate_report_candidate(snapshot, policy)
    if (
        not isinstance(findings, Sequence)
        or len(findings) > MAX_TOTAL_FINDINGS + 1
    ):
        raise AuditInputError("report findings are invalid")
    policy_payload = _policy_bytes(snapshot.root, policy)
    scanner_payload = _read_absolute_regular_file(
        Path(__file__), MAX_BLOB_BYTES, "scanner source"
    )
    finding_payloads = sorted(
        (_finding_payload(item) for item in findings),
        key=lambda item: (
            item["rule_id"], item["classification"], item["path"],
            item["location"], item["message"]
        )
    )
    check_payload = _validated_checks(checks)
    refs = dict(snapshot.refs)
    tree_ids = {
        ref: _git(
            snapshot.root,
            "rev-parse",
            "--verify",
            f"{object_id}^{{tree}}",
            repository_config=snapshot.git_config
        ).decode("ascii", "strict").strip()
        for ref, object_id in snapshot.refs
    }
    gitleaks_version = _actual_gitleaks_version(policy)
    tools = {
        "git": _git(
            snapshot.root,
            "--version",
            repository_config=snapshot.git_config
        ).decode("utf-8", "strict").strip(),
        "gitleaks": gitleaks_version,
        "python": platform.python_version(),
    }
    if any(
        not value
        or len(value) > 240
        or _has_control_characters(value)
        or ABSOLUTE_PATH_TEXT.search(value)
        for value in tools.values()
    ):
        raise AuditInputError("tool version is invalid")
    payload: dict[str, object] = {
        "schema_version": 1,
        "repository": policy.repository,
        "intended_remote": f"https://github.com/{policy.repository}.git",
        "intended_visibility": "public",
        "refs": refs,
        "tree_ids": tree_ids,
        "scanner_sha256": hash_bytes(scanner_payload),
        "policy_sha256": hash_bytes(policy_payload),
        "exception_sha256": [
            hash_bytes(canonical_json(dataclasses.asdict(item)))
            for item in (
                *policy.path_exceptions, *policy.synthetic_exceptions
            )
        ],
        "manual_documents": _document_digests(snapshot.root, policy),
        "tools": tools,
        "audit_scope": (
            "local"
            if frozenset(check_payload) == LOCAL_CHECK_NAMES
            else "publication"
            if frozenset(check_payload) == PUBLICATION_CHECK_NAMES
            else "unsupported"
        ),
        "checks": check_payload,
        "finding_count": len(finding_payloads),
        "findings": finding_payloads,
        "result": (
            "pass"
            if (
                not finding_payloads
                and check_payload
                and all(
                    value == "pass"
                    for value in check_payload.values()
                )
            )
            else "fail"
        ),
    }
    _validate_report_candidate(snapshot, policy)
    if _policy_bytes(snapshot.root, policy) != policy_payload:
        raise AuditInputError("policy changed during report generation")
    return payload


def write_report(
    snapshot: RepositorySnapshot,
    policy: Policy,
    findings: Sequence[Finding],
    checks: Mapping[str, str]
) -> Path:
    payload = report_payload(snapshot, policy, findings, checks)
    body = canonical_json(payload)
    if len(body) > MAX_REPORT_BYTES:
        raise AuditInputError("report exceeds the private artifact limit")
    state_descriptor = -1
    try:
        state_descriptor, state = _private_state_descriptor(
            snapshot.root, create=True
        )
        _atomic_write_private(
            state_descriptor,
            "report.json",
            body,
            AuditInputError,
            "report"
        )
        return state / "report.json"
    finally:
        if state_descriptor >= 0:
            os.close(state_descriptor)


def _decode_canonical_object(
    payload: bytes,
    context: str
) -> dict[str, object]:
    try:
        decoded = json.loads(
            payload.decode("ascii", "strict"),
            object_pairs_hook=_object_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("invalid JSON constant")
            )
        )
        if not isinstance(decoded, dict) or canonical_json(decoded) != payload:
            raise ValueError("non-canonical object")
        return decoded
    except (
        UnicodeError, json.JSONDecodeError, PolicyError,
        TypeError, ValueError, RecursionError
    ):
        raise AuditInputError(f"{context} is not canonical JSON") from None


def _digest_value(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _validated_report(
    report: dict[str, object]
) -> tuple[
    tuple[Finding, ...],
    dict[str, str],
    dict[str, str]
]:
    if set(report) != REPORT_KEYS or type(
        report.get("schema_version")
    ) is not int or report["schema_version"] != 1:
        raise AuditInputError("report schema is invalid")
    refs = report.get("refs")
    trees = report.get("tree_ids")
    if (
        not isinstance(refs, dict)
        or not refs
        or not isinstance(trees, dict)
        or set(trees) != set(refs)
    ):
        raise AuditInputError("report refs are invalid")
    ref_payload: dict[str, str] = {}
    for ref, object_id in refs.items():
        if (
            not isinstance(ref, str)
            or not ref.startswith(("refs/heads/", "refs/tags/"))
            or _has_control_characters(ref)
            or not isinstance(object_id, str)
            or re.fullmatch(r"[0-9a-f]{40,64}", object_id) is None
            or not (
                isinstance(trees.get(ref), str)
                and re.fullmatch(
                    r"[0-9a-f]{40,64}", trees[ref]
                ) is not None
            )
        ):
            raise AuditInputError("report refs are invalid")
        ref_payload[ref] = object_id
    checks_value = report.get("checks")
    if not isinstance(checks_value, dict):
        raise AuditInputError("report checks are invalid")
    checks = _validated_checks(checks_value)
    if report.get("audit_scope") not in {
        "local", "publication", "unsupported"
    }:
        raise AuditInputError("report audit scope is invalid")
    raw_findings = report.get("findings")
    if not isinstance(raw_findings, list):
        raise AuditInputError("report findings are invalid")
    findings: list[Finding] = []
    for raw in raw_findings:
        if not isinstance(raw, dict) or set(raw) != {
            "rule_id", "classification", "path", "location", "message"
        }:
            raise AuditInputError("report findings are invalid")
        try:
            finding = Finding(**raw)
        except TypeError:
            raise AuditInputError("report findings are invalid") from None
        _finding_payload(finding)
        findings.append(finding)
    finding_count = report.get("finding_count")
    expected_result = (
        "pass"
        if (
            not findings
            and checks
            and all(value == "pass" for value in checks.values())
        )
        else "fail"
    )
    exception_sha256 = report.get("exception_sha256")
    manual_documents = report.get("manual_documents")
    tools = report.get("tools")
    if (
        type(finding_count) is not int
        or finding_count != len(findings)
        or report.get("result") != expected_result
        or not all(_digest_value(report.get(name)) for name in (
            "scanner_sha256", "policy_sha256"
        ))
        or not isinstance(exception_sha256, list)
        or not all(_digest_value(item) for item in exception_sha256)
        or not isinstance(manual_documents, dict)
        or not all(
            isinstance(name, str) and _digest_value(value)
            for name, value in manual_documents.items()
        )
        or not isinstance(tools, dict)
        or set(tools) != {"git", "gitleaks", "python"}
        or not all(
            isinstance(value, str) and value
            for value in tools.values()
        )
        or not isinstance(report.get("repository"), str)
        or report.get("intended_remote") != (
            f"https://github.com/{report['repository']}.git"
        )
        or report.get("intended_visibility") != "public"
    ):
        raise AuditInputError("report binding is invalid")
    return tuple(findings), checks, ref_payload


def _current_report(
    root: Path,
    body: bytes
) -> dict[str, object]:
    report = _decode_canonical_object(body, "report")
    findings, checks, approved_refs = _validated_report(report)
    try:
        policy = load_policy(root / ".public-repository-safety.json")
        selected = select_public_refs(root, policy)
        snapshot = resolve_repository(root, selected, policy)
    except (PolicyError, AuditInputError, OSError, UnicodeError):
        raise AuditInputError("report is stale") from None
    if dict(snapshot.refs) != approved_refs:
        raise AuditInputError("report refs are stale")
    current = report_payload(snapshot, policy, findings, checks)
    if canonical_json(current) != body:
        raise AuditInputError("report is stale")
    return report


def _independent_publication_report(
    root: Path,
) -> tuple[
    dict[str, object],
    RepositorySnapshot,
    Policy,
    bytes,
]:
    try:
        policy = load_policy(root / ".public-repository-safety.json")
        selected = select_public_refs(root, policy)
        snapshot = resolve_repository(root, selected, policy)
        git_findings = scan_git(snapshot, policy)
        leak_findings = scan_gitleaks(snapshot, policy)
        state = inspect_github(snapshot, policy)
        remote_findings = state.findings
        findings = (
            *git_findings,
            *leak_findings,
            *remote_findings,
        )
        checks = {
            "git": "pass" if not git_findings else "fail",
            "gitleaks": "pass" if not leak_findings else "fail",
            "github": "pass" if not remote_findings else "fail",
        }
        report = report_payload(
            snapshot, policy, findings, checks
        )
        body = canonical_json(report)
    except (
        PolicyError,
        ToolError,
        AuditInputError,
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        RecursionError,
    ):
        raise AuditInputError(
            "independent approval evidence is unavailable"
        ) from None
    if (
        not state.complete
        or not state.candidate_bound
        or state.visibility not in {"private", "public"}
        or findings
        or not _publication_report_eligible(report)
        or len(body) > MAX_REPORT_BYTES
    ):
        raise AuditInputError(
            "independent approval evidence did not pass"
        )
    return report, snapshot, policy, body


def _receipt_payload(
    report: Mapping[str, object],
    report_digest: str,
    approval_id: str,
    transaction_id: str
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "report_digest": report_digest,
        "approval_id": approval_id,
        "repository": report["repository"],
        "intended_remote": report["intended_remote"],
        "intended_visibility": report["intended_visibility"],
        "refs": report["refs"],
        "tree_ids": report["tree_ids"],
        "scanner_sha256": report["scanner_sha256"],
        "policy_sha256": report["policy_sha256"],
        "exception_sha256": report["exception_sha256"],
        "manual_documents": report["manual_documents"],
        "tools": report["tools"],
        "audit_scope": report["audit_scope"],
        "checks": report["checks"],
        "finding_count": report["finding_count"],
        "result": report["result"],
    }


def _approval_transaction_payload(
    transaction_id: str,
    report_digest: str,
    approval_id: str,
    receipt_body: bytes
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "report_digest": report_digest,
        "approval_id": approval_id,
        "receipt_sha256": hash_bytes(receipt_body),
    }


def _validated_approval_transaction(
    body: bytes
) -> dict[str, object]:
    transaction = _decode_canonical_object(
        body, "approval transaction"
    )
    if (
        set(transaction) != APPROVAL_TRANSACTION_KEYS
        or type(transaction.get("schema_version")) is not int
        or transaction["schema_version"] != 1
        or not _digest_value(transaction.get("transaction_id"))
        or not _digest_value(transaction.get("report_digest"))
        or not _digest_value(transaction.get("receipt_sha256"))
        or not isinstance(transaction.get("approval_id"), str)
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}",
            transaction["approval_id"]
        ) is None
    ):
        raise AuditInputError("approval transaction is invalid")
    return transaction


def approve_report(
    root: Path,
    report_digest: str,
    approval_id: str
) -> Path:
    if (
        not isinstance(report_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", report_digest) is None
    ):
        raise ApprovalError("report digest is invalid")
    if (
        not isinstance(approval_id, str)
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", approval_id
        ) is None
    ):
        raise ApprovalError("approval identifier is invalid")
    state_descriptor = -1
    try:
        try:
            state_descriptor, state = _private_state_descriptor(
                root, create=False
            )
            report_body = _read_private_artifact(
                state_descriptor, "report.json", MAX_REPORT_BYTES
            )
        except AuditInputError:
            raise ApprovalError(
                "private passing report is unavailable or unsafe"
            ) from None
        if hash_bytes(report_body) != report_digest:
            raise ApprovalError(
                "approved report digest does not match"
            )
        preliminary = _decode_canonical_object(report_body, "report")
        _validated_report(preliminary)
        if preliminary.get("result") != "pass":
            raise ApprovalError("approval requires a passing report")
        if not _publication_checks_pass(preliminary):
            raise ApprovalError(
                "approval requires complete passing public checks"
            )
        try:
            report, snapshot, policy, independent_body = (
                _independent_publication_report(root)
            )
        except AuditInputError:
            raise ApprovalError(
                "approval requires independently verified evidence"
            ) from None
        if (
            independent_body != report_body
            or hash_bytes(independent_body) != report_digest
        ):
            raise ApprovalError(
                "approved report differs from independent evidence"
            )
        _validate_report_candidate(snapshot, policy)
        if _read_private_artifact(
            state_descriptor, "report.json", MAX_REPORT_BYTES
        ) != report_body:
            raise ApprovalError("approved report changed during verification")
        transaction_id = secrets.token_hex(32)
        receipt_body = canonical_json(_receipt_payload(
            report, report_digest, approval_id, transaction_id
        ))
        if len(receipt_body) > MAX_RECEIPT_BYTES:
            raise ApprovalError("approval receipt exceeds the private limit")
        transaction_body = canonical_json(_approval_transaction_payload(
            transaction_id, report_digest, approval_id, receipt_body
        ))
        if len(transaction_body) > MAX_APPROVAL_TRANSACTION_BYTES:
            raise ApprovalError(
                "approval transaction exceeds the private limit"
            )
        _atomic_write_private(
            state_descriptor,
            APPROVAL_INTENT_NAME,
            transaction_body,
            ApprovalError,
            "approval receipt intent"
        )
        try:
            _atomic_write_private(
                state_descriptor,
                "approval.json",
                receipt_body,
                ApprovalError,
                "approval receipt"
            )
            if _read_private_artifact(
                state_descriptor, "approval.json", MAX_RECEIPT_BYTES
            ) != receipt_body:
                raise ApprovalError(
                    "approval receipt could not be verified"
                )
            if _read_private_artifact(
                state_descriptor,
                APPROVAL_INTENT_NAME,
                MAX_APPROVAL_TRANSACTION_BYTES
            ) != transaction_body:
                raise ApprovalError(
                    "approval receipt intent could not be verified"
                )
        except (ApprovalError, AuditInputError):
            raise ApprovalError(
                "approval receipt could not be committed"
            ) from None
        prepared_commit = _prepare_private_replacement(
            state_descriptor,
            APPROVAL_COMMITTED_NAME,
            transaction_body,
            ApprovalError,
            "committed approval receipt record"
        )
        receipt_path = state / "approval.json"
        try:
            # This replace is the commit point. Do not add verification,
            # cleanup, or directory sync after it: an absent or stale record
            # is safe, while a matching record is positive commit evidence.
            os.replace(
                prepared_commit,
                APPROVAL_COMMITTED_NAME,
                src_dir_fd=state_descriptor,
                dst_dir_fd=state_descriptor
            )
        except OSError:
            try:
                os.unlink(prepared_commit, dir_fd=state_descriptor)
            except OSError:
                pass
            raise ApprovalError(
                "committed approval receipt record could not be installed"
            ) from None
        return receipt_path
    except AuditInputError:
        raise ApprovalError("report is invalid or stale") from None
    finally:
        if state_descriptor >= 0:
            try:
                os.close(state_descriptor)
            except OSError:
                pass


def verify_receipt(
    root: Path,
    report_digest: str,
    pushed_refs: Mapping[str, str]
) -> bool:
    if (
        not isinstance(report_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", report_digest) is None
        or not isinstance(pushed_refs, Mapping)
        or not pushed_refs
    ):
        return False
    try:
        pushed = dict(pushed_refs)
        if any(
            not isinstance(ref, str)
            or not isinstance(object_id, str)
            or re.fullmatch(
                r"[0-9a-f]{40,64}", object_id
            ) is None
            for ref, object_id in pushed.items()
        ):
            return False
        state_descriptor, _ = _private_state_descriptor(
            root, create=False
        )
        try:
            report_body = _read_private_artifact(
                state_descriptor, "report.json", MAX_REPORT_BYTES
            )
            receipt_body = _read_private_artifact(
                state_descriptor, "approval.json", MAX_RECEIPT_BYTES
            )
            intent_body = _read_private_artifact(
                state_descriptor,
                APPROVAL_INTENT_NAME,
                MAX_APPROVAL_TRANSACTION_BYTES
            )
            committed_body = _read_private_artifact(
                state_descriptor,
                APPROVAL_COMMITTED_NAME,
                MAX_APPROVAL_TRANSACTION_BYTES
            )
            if intent_body != committed_body:
                return False
            if hash_bytes(report_body) != report_digest:
                return False
            report = _current_report(root, report_body)
            if not _publication_report_eligible(report):
                return False
            approved_refs = report.get("refs")
            if (
                not isinstance(approved_refs, dict)
                or any(
                    approved_refs.get(ref) != object_id
                    for ref, object_id in pushed.items()
                )
            ):
                return False
            receipt = _decode_canonical_object(receipt_body, "receipt")
            approval_id = receipt.get("approval_id")
            transaction_id = receipt.get("transaction_id")
            if (
                set(receipt) != RECEIPT_KEYS
                or not isinstance(approval_id, str)
                or re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", approval_id
                ) is None
                or not _digest_value(transaction_id)
            ):
                return False
            expected = _receipt_payload(
                report, report_digest, approval_id, transaction_id
            )
            if canonical_json(expected) != receipt_body:
                return False
            transaction = _validated_approval_transaction(intent_body)
            expected_transaction = _approval_transaction_payload(
                transaction_id, report_digest, approval_id, receipt_body
            )
            return (
                canonical_json(expected_transaction) == intent_body
                and _read_private_artifact(
                    state_descriptor,
                    APPROVAL_INTENT_NAME,
                    MAX_APPROVAL_TRANSACTION_BYTES
                ) == intent_body
                and _read_private_artifact(
                    state_descriptor,
                    APPROVAL_COMMITTED_NAME,
                    MAX_APPROVAL_TRANSACTION_BYTES
                ) == committed_body
            )
        finally:
            os.close(state_descriptor)
    except (
        AuditInputError, OSError, UnicodeError, TypeError,
        ValueError, KeyError
    ):
        return False


class RemoteProtectionError(AuditInputError):
    pass


@dataclass(frozen=True)
class PrePushUpdate:
    local_ref: str
    local_oid: str
    remote_ref: str
    remote_oid: str
    deletion: bool


PRE_PUSH_MAX_UPDATES = 100
PRE_PUSH_MAX_LINE_CHARS = 4096
REMOTE_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
GIT_REF_FORBIDDEN = re.compile(r"[\x00-\x20\x7f~^:?*\\[]")
CI_GITLEAKS_SHA256 = (
    "551f6fc83ea457d62a0d98237cbad105"
    "af8d557003051f41f3e7ca7b3f2470eb"
)
OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
CI_WORKFLOW = """name: Public repository safety
on:
  push:
  pull_request:
permissions:
  contents: read
jobs:
  safety:
    name: Public repository safety
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10
        with:
          fetch-depth: 0
          lfs: true
          persist-credentials: false
      - name: Remove checkout-installed Git LFS filters
        run: git config --local --remove-section filter.lfs
      - name: Install pinned Gitleaks
        env:
          GITLEAKS_VERSION: 8.30.1
          GITLEAKS_SHA256: 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
        run: |
          set -euo pipefail
          python3 -c 'import sys; assert sys.version_info[:2] == (3, 12)'
          archive="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
          curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \\
            --output "$RUNNER_TEMP/$archive" \\
            "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/$archive"
          printf '%s  %s\\n' "$GITLEAKS_SHA256" "$RUNNER_TEMP/$archive" | sha256sum --check --strict
          tar -xzf "$RUNNER_TEMP/$archive" -C "$RUNNER_TEMP" gitleaks
          chmod 0755 "$RUNNER_TEMP/gitleaks"
          echo "$RUNNER_TEMP" >> "$GITHUB_PATH"
      - name: Audit complete intended public history
        run: python3 .github/scripts/public-repository-safety.py audit --repo "$GITHUB_WORKSPACE" --local-only
"""


def _valid_git_ref(value: str) -> bool:
    if (
        not isinstance(value, str)
        or not value.startswith("refs/")
        or len(value.encode("utf-8")) > 1024
        or value.endswith(("/", "."))
        or "//" in value
        or ".." in value
        or "@{" in value
        or GIT_REF_FORBIDDEN.search(value) is not None
    ):
        return False
    components = value.split("/")
    return (
        len(components) >= 3
        and all(
            component
            and not component.startswith(".")
            and not component.endswith(".lock")
            for component in components
        )
    )


def parse_pre_push(stdin: TextIO) -> tuple[PrePushUpdate, ...]:
    updates: list[PrePushUpdate] = []
    local_refs: set[str] = set()
    remote_refs: set[str] = set()
    object_width: int | None = None
    while True:
        line = stdin.readline(PRE_PUSH_MAX_LINE_CHARS + 1)
        if line == "":
            break
        if (
            not isinstance(line, str)
            or len(line) > PRE_PUSH_MAX_LINE_CHARS
            or not line.endswith("\n")
            or line.endswith("\r\n")
            or line.count(" ") != 3
            or _has_control_characters(line[:-1])
        ):
            raise AuditInputError("pre-push input is malformed")
        fields = line[:-1].split(" ")
        if len(fields) != 4 or any(not field for field in fields):
            raise AuditInputError("pre-push input is malformed")
        local_ref, local_oid, remote_ref, remote_oid = fields
        if (
            re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", local_oid)
            is None
            or re.fullmatch(
                r"[0-9a-f]{40}|[0-9a-f]{64}", remote_oid
            )
            is None
            or len(local_oid) != len(remote_oid)
        ):
            raise AuditInputError(
                "pre-push object identity is malformed"
            )
        if object_width is None:
            object_width = len(local_oid)
        elif object_width != len(local_oid):
            raise AuditInputError(
                "pre-push object identity is malformed"
            )
        local_zero = set(local_oid) == {"0"}
        remote_zero = set(remote_oid) == {"0"}
        deletion = local_ref == "(delete)"
        if (
            local_zero != deletion
            or (local_zero and remote_zero)
            or (not deletion and not _valid_git_ref(local_ref))
            or not _valid_git_ref(remote_ref)
            or remote_ref in remote_refs
            or (
                not deletion
                and local_ref in local_refs
            )
        ):
            raise AuditInputError("pre-push ref update is malformed")
        remote_refs.add(remote_ref)
        if not deletion:
            local_refs.add(local_ref)
        updates.append(PrePushUpdate(
            local_ref,
            local_oid,
            remote_ref,
            remote_oid,
            deletion,
        ))
        if len(updates) > PRE_PUSH_MAX_UPDATES:
            raise AuditInputError("pre-push update limit was exceeded")
    return tuple(updates)


def _canonical_repository_root(root: Path) -> Path:
    if not isinstance(root, Path):
        raise AuditInputError("repository root is invalid")
    try:
        if root.is_symlink():
            raise AuditInputError("repository root is unsafe")
        canonical = root.resolve(strict=True)
        info = canonical.stat()
    except OSError:
        raise AuditInputError("repository root is unavailable") from None
    if (
        canonical != root.absolute()
        or not stat.S_ISDIR(info.st_mode)
    ):
        raise AuditInputError("repository root is unsafe")
    return canonical


def _configured_push_remote(root: Path, remote_name: str) -> str:
    root = _canonical_repository_root(root)
    if (
        not isinstance(remote_name, str)
        or REMOTE_NAME_PATTERN.fullmatch(remote_name) is None
    ):
        raise RemoteProtectionError("configured push remote is invalid")
    repository_config = _repository_config(root)
    try:
        names = _remote_names(
            root, repository_config=repository_config
        )
        urls = _git(
            root,
            "remote",
            "get-url",
            "--push",
            "--all",
            remote_name,
            repository_config=repository_config,
        ).decode("utf-8", "strict").splitlines()
    except (AuditInputError, UnicodeError):
        raise RemoteProtectionError(
            "configured push remote is unavailable"
        ) from None
    if (
        remote_name not in names
        or len(urls) != 1
        or not urls[0]
        or _has_control_characters(urls[0])
    ):
        raise RemoteProtectionError(
            "configured push remote is absent or ambiguous"
        )
    return urls[0]


def _remote_names(
    root: Path,
    *,
    repository_config: Sequence[tuple[str, str]] | None = None,
) -> tuple[str, ...]:
    if repository_config is None:
        repository_config = _repository_config(root)
    try:
        names = tuple(
            _git(
                root,
                "remote",
                repository_config=repository_config,
            ).decode("utf-8", "strict").splitlines()
        )
    except (AuditInputError, UnicodeError):
        raise RemoteProtectionError(
            "configured remotes are unavailable"
        ) from None
    if (
        len(names) != len(set(names))
        or any(
            REMOTE_NAME_PATTERN.fullmatch(name) is None
            for name in names
        )
    ):
        raise RemoteProtectionError(
            "configured remotes are ambiguous"
        )
    return names


def _private_report_digest(root: Path) -> str:
    state_descriptor = -1
    try:
        state_descriptor, _ = _private_state_descriptor(
            root, create=False
        )
        body = _read_private_artifact(
            state_descriptor, "report.json", MAX_REPORT_BYTES
        )
        return hash_bytes(body)
    finally:
        if state_descriptor >= 0:
            os.close(state_descriptor)


def _github_push_identity(
    repository: str,
    runner: Runner,
) -> tuple[int, str]:
    metadata = _gh_json(repository, "", runner)
    if not isinstance(metadata, dict):
        raise AuditInputError("GitHub push identity is invalid")
    owner_name, repository_name = repository.split("/", 1)
    owner = metadata.get("owner")
    visibility = metadata.get("visibility")
    if (
        not _positive_integer(metadata.get("id"))
        or metadata.get("full_name") != repository
        or metadata.get("name") != repository_name
        or not isinstance(owner, dict)
        or owner.get("login") != owner_name
        or visibility not in {"private", "public"}
        or type(metadata.get("private")) is not bool
        or metadata["private"] != (visibility == "private")
    ):
        raise AuditInputError("GitHub push identity is invalid")
    return metadata["id"], visibility


def inspect_github_push_target(
    repository: str,
    policy: Policy,
    runner: Runner = run_github_command,
) -> GitHubState:
    if not isinstance(policy, Policy) or repository != policy.repository:
        raise AuditInputError("GitHub push repository does not match policy")
    runner = _InspectionRunner(runner)
    _github_authenticated(runner)
    identity = _github_push_identity(repository, runner)
    if identity[1] == "private":
        if _github_push_identity(repository, runner) != identity:
            raise AuditInputError("GitHub push identity changed during inspection")
        # Private upload enables bootstrap; it is never publication evidence.
        return GitHubState("private", "", True, (), False)

    state = inspect_github_identity(repository, policy, runner)
    if not state.complete:
        return state
    if (
        state.visibility != "public"
        or _github_push_identity(repository, runner) != identity
    ):
        raise AuditInputError("GitHub push identity changed during inspection")
    return state


def main_pre_push(
    argv: Sequence[str] | None = None,
    stdin: TextIO = sys.stdin,
    runner: Runner = run_github_command,
) -> int:
    parser = argparse.ArgumentParser(prog="pre-push")
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--remote-name", required=True)
    parser.add_argument("--remote-url", required=True)
    arguments = parser.parse_args(argv)
    try:
        root = _canonical_repository_root(arguments.repo)
        updates = parse_pre_push(stdin)
        policy = load_policy(
            root / ".public-repository-safety.json"
        )
        configured_url = _configured_push_remote(
            root, arguments.remote_name
        )
        if (
            arguments.remote_url != configured_url
            or github_repository_from_remote(configured_url)
            != policy.repository
        ):
            return ExitCode.REMOTE_OR_PROTECTION
        state = inspect_github_push_target(
            policy.repository, policy, runner
        )
        if not state.complete:
            return ExitCode.INCOMPLETE_SURFACE
        if state.visibility == "private":
            return ExitCode.PASS
        if (
            state.visibility != "public"
            or state.findings
            or any(update.deletion for update in updates)
        ):
            return ExitCode.REMOTE_OR_PROTECTION
        pushed_refs = {
            update.remote_ref: update.local_oid
            for update in updates
        }
        if not pushed_refs:
            return ExitCode.APPROVAL
        try:
            report_digest = _private_report_digest(root)
        except AuditInputError:
            return ExitCode.APPROVAL
        return (
            ExitCode.PASS
            if verify_receipt(root, report_digest, pushed_refs)
            else ExitCode.APPROVAL
        )
    except PolicyError:
        return ExitCode.POLICY_OR_CONTENT
    except RemoteProtectionError:
        return ExitCode.REMOTE_OR_PROTECTION
    except (
        AuditInputError,
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
    ):
        return ExitCode.TOOLING_OR_INPUT


def _safe_install_parent(path: Path) -> None:
    descriptor = -1
    try:
        descriptor = _open_directory_nofollow(path)
        info = os.fstat(descriptor)
        current_uid = getattr(
            os, "geteuid", lambda: info.st_uid
        )()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != current_uid
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise AuditInputError("installation parent is unsafe")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_directory_nofollow(path: Path) -> int:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or not OPEN_SUPPORTS_DIR_FD
    ):
        raise AuditInputError(
            "no-follow installation path access is unavailable"
        )
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path.anchor, flags)
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component, flags, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        raise AuditInputError(
            "installation parent is unavailable or unsafe"
        ) from None


def _target_absent(path: Path, description: str) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise AuditInputError(
            f"{description} is unavailable"
        ) from None
    raise AuditInputError(f"existing {description} requires review")


def _revalidate_install_directory(
    path: Path,
    identity: tuple[int, int],
) -> None:
    current = _open_directory_nofollow(path)
    try:
        info = os.fstat(current)
        if (info.st_dev, info.st_ino) != identity:
            raise AuditInputError("installation parent changed")
    finally:
        os.close(current)


def _exclusive_install_file(
    path: Path,
    payload: bytes,
    mode: int,
) -> tuple[str, tuple[int, int]]:
    directory_descriptor = -1
    file_descriptor = -1
    try:
        _safe_install_parent(path.parent)
        directory_descriptor = _open_directory_nofollow(
            path.parent
        )
        directory_info = os.fstat(directory_descriptor)
        directory_identity = (
            directory_info.st_dev,
            directory_info.st_ino,
        )
        file_descriptor = os.open(
            path.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        os.fchmod(file_descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError(errno.EIO, "short install write")
            view = view[written:]
        os.fsync(file_descriptor)
        os.fchmod(file_descriptor, mode)
        os.fsync(file_descriptor)
        info = os.fstat(file_descriptor)
        identity = (info.st_dev, info.st_ino)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != mode
            or info.st_size != len(payload)
            or _name_identity(
                directory_descriptor, path.name
            ) != identity
        ):
            raise OSError(errno.EIO, "invalid installed file")
        _revalidate_install_directory(
            path.parent, directory_identity
        )
        os.fsync(directory_descriptor)
        return path.name, identity
    except OSError:
        raise AuditInputError(
            "installation could not be committed safely"
        ) from None
    finally:
        if file_descriptor >= 0:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        if directory_descriptor >= 0:
            try:
                os.close(directory_descriptor)
            except OSError:
                pass


def _name_identity(
    directory_descriptor: int,
    name: str,
) -> tuple[int, int] | None:
    try:
        info = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except OSError:
        return None
    return info.st_dev, info.st_ino


def _managed_install_state(
    path: Path,
    payload: bytes,
    mode: int,
) -> str:
    directory_descriptor = -1
    file_descriptor = -1
    try:
        _safe_install_parent(path.parent)
        directory_descriptor = _open_directory_nofollow(
            path.parent
        )
        directory_info = os.fstat(directory_descriptor)
        directory_identity = (
            directory_info.st_dev,
            directory_info.st_ino,
        )
        try:
            named_info = os.stat(
                path.name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return "absent"
        if not stat.S_ISREG(named_info.st_mode):
            return "review"
        try:
            file_descriptor = os.open(
                path.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_descriptor,
            )
        except OSError:
            return "review"
        before = os.fstat(file_descriptor)
        try:
            body = _read_bounded_descriptor(
                file_descriptor, len(payload)
            )
        except AuditInputError:
            return "review"
        after = os.fstat(file_descriptor)
        identity = (before.st_dev, before.st_ino)
        _revalidate_install_directory(
            path.parent, directory_identity
        )
        if (
            _config_stat_identity(before)
            != _config_stat_identity(after)
            or _name_identity(
                directory_descriptor, path.name
            ) != identity
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_size != len(payload)
            or body != payload
        ):
            return "review"
        return "managed"
    except OSError:
        raise AuditInputError(
            "installation target is unavailable or unsafe"
        ) from None
    finally:
        if file_descriptor >= 0:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        if directory_descriptor >= 0:
            try:
                os.close(directory_descriptor)
            except OSError:
                pass


def install_hook(root: Path) -> Path:
    root = _canonical_repository_root(root)
    config_snapshot = _repository_config_snapshot(root)
    repository_config = config_snapshot.values
    try:
        common_dir = Path(_git(
            root,
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
            repository_config=repository_config,
        ).decode("utf-8", "strict").strip())
        hooks = Path(_git(
            root,
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "hooks",
            repository_config=repository_config,
        ).decode("utf-8", "strict").strip())
    except (AuditInputError, UnicodeError):
        raise AuditInputError("Git hook path is unavailable") from None
    if (
        hooks != common_dir / "hooks"
        or common_dir != config_snapshot.common_dir
    ):
        raise AuditInputError("Git hook path is unsafe")
    _safe_install_parent(hooks)
    hook = hooks / "pre-push"
    _target_absent(hook, "pre-push hook")
    uv = shutil.which("uv")
    entry = Path(__file__).resolve().with_name("pre_push.py")
    if (
        uv is None
        or not Path(uv).is_absolute()
        or not Path(uv).is_file()
        or entry.is_symlink()
        or not entry.is_file()
    ):
        raise AuditInputError(
            "uv and the managed pre-push entrypoint are required"
        )
    body = (
        "#!/bin/sh\n"
        "set -eu\n"
        f"exec {shlex.quote(uv)} run --python 3.12 "
        f"{shlex.quote(os.fspath(entry))} "
        f"--repo {shlex.quote(os.fspath(root))} "
        '--remote-name "$1" --remote-url "$2"\n'
    ).encode()
    _exclusive_install_file(hook, body, 0o700)
    return hook


def _preflight_ci_path(root: Path, parts: Sequence[str]) -> None:
    current = root
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return
        except OSError:
            raise AuditInputError("CI installation path is unavailable")
        if stat.S_ISLNK(info.st_mode):
            raise AuditInputError("CI installation path is unsafe")
        if (
            current != root.joinpath(*parts)
            and not stat.S_ISDIR(info.st_mode)
        ):
            raise AuditInputError("CI installation path is unsafe")


def _ensure_ci_directory(path: Path) -> None:
    parent_descriptor = -1
    directory_descriptor = -1
    try:
        if os.mkdir not in os.supports_dir_fd:
            raise AuditInputError(
                "descriptor-relative directory creation is unavailable"
            )
        _safe_install_parent(path.parent)
        parent_descriptor = _open_directory_nofollow(path.parent)
        parent_info = os.fstat(parent_descriptor)
        parent_identity = (
            parent_info.st_dev,
            parent_info.st_ino,
        )
        try:
            named_info = os.stat(
                path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            os.mkdir(path.name, 0o755, dir_fd=parent_descriptor)
        else:
            if not stat.S_ISDIR(named_info.st_mode):
                raise AuditInputError(
                    "CI installation path is unsafe"
                )
        flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        directory_descriptor = os.open(
            path.name,
            flags,
            dir_fd=parent_descriptor,
        )
        info = os.fstat(directory_descriptor)
        current_uid = getattr(
            os, "geteuid", lambda: info.st_uid
        )()
        identity = (info.st_dev, info.st_ino)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != current_uid
            or stat.S_IMODE(info.st_mode) & 0o022
            or _name_identity(
                parent_descriptor, path.name
            ) != identity
        ):
            raise AuditInputError("CI installation path is unsafe")
        _revalidate_install_directory(
            path.parent, parent_identity
        )
    except OSError:
        raise AuditInputError("CI installation path is unavailable") from None
    finally:
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def install_ci(root: Path) -> tuple[Path, Path]:
    root = _canonical_repository_root(root)
    script = (
        root
        / ".github"
        / "scripts"
        / "public-repository-safety.py"
    )
    workflow = (
        root
        / ".github"
        / "workflows"
        / "public-repository-safety.yml"
    )
    for target in (script, workflow):
        _preflight_ci_path(root, target.relative_to(root).parts)
    github = root / ".github"
    _ensure_ci_directory(github)
    _ensure_ci_directory(github / "scripts")
    _ensure_ci_directory(github / "workflows")
    scanner_payload = _read_absolute_regular_file(
        Path(__file__), MAX_BLOB_BYTES, "scanner source"
    )
    workflow_payload = CI_WORKFLOW.encode("utf-8")
    workflow_state = _managed_install_state(
        workflow, workflow_payload, 0o644
    )
    if workflow_state != "absent":
        raise AuditInputError(
            "existing CI workflow requires review"
        )
    scanner_state = _managed_install_state(
        script, scanner_payload, 0o755
    )
    if scanner_state == "review":
        raise AuditInputError(
            "existing CI scanner requires review"
        )
    if scanner_state == "absent":
        _exclusive_install_file(script, scanner_payload, 0o755)
    if (
        _managed_install_state(
            script, scanner_payload, 0o755
        )
        != "managed"
    ):
        raise AuditInputError("CI scanner is unavailable or unsafe")
    _exclusive_install_file(workflow, workflow_payload, 0o644)
    if (
        _managed_install_state(
            script, scanner_payload, 0o755
        )
        != "managed"
        or _managed_install_state(
            workflow, workflow_payload, 0o644
        )
        != "managed"
    ):
        raise AuditInputError("CI installation is unavailable or unsafe")
    return script, workflow


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="public-repository-safety"
    )
    commands = parser.add_subparsers(
        dest="command", required=True
    )
    audit = commands.add_parser("audit")
    audit.add_argument("--repo", required=True, type=Path)
    audit.add_argument("--remote", default="origin")
    audit.add_argument(
        "--format", choices=("human", "json"), default="human"
    )
    audit.add_argument("--local-only", action="store_true")
    approve = commands.add_parser("approve")
    approve.add_argument("--repo", required=True, type=Path)
    approve.add_argument("--report-digest", required=True)
    approve.add_argument("--approval-id", required=True)
    for name in ("install-hook", "install-ci", "inspect-remote"):
        command = commands.add_parser(name)
        command.add_argument("--repo", required=True, type=Path)
        if name == "inspect-remote":
            command.add_argument("--remote", default="origin")
    create = commands.add_parser("check-create")
    create.add_argument(
        "--visibility",
        choices=("private", "public"),
        required=True,
    )
    return parser


def _audit_repository(
    root: Path,
    remote_name: str,
    output_format: str,
    local_only: bool = False,
) -> ExitCode:
    policy = load_policy(
        root / ".public-repository-safety.json"
    )
    remote_names = () if local_only else _remote_names(root)
    if remote_names:
        configured_url = _configured_push_remote(
            root, remote_name
        )
        if (
            github_repository_from_remote(configured_url)
            != policy.repository
        ):
            raise RemoteProtectionError(
                "intended remote does not match policy"
            )
    selected = select_public_refs(root, policy)
    snapshot = resolve_repository(root, selected, policy)
    git_findings = scan_git(snapshot, policy)
    leak_findings = scan_gitleaks(snapshot, policy)
    state: GitHubState | None = None
    if remote_names:
        state = inspect_github(snapshot, policy)
        if not state.complete:
            return ExitCode.INCOMPLETE_SURFACE
    remote_findings = state.findings if state is not None else ()
    findings = (
        *git_findings,
        *leak_findings,
        *remote_findings,
    )
    checks = {
        "git": "pass" if not git_findings else "fail",
        "gitleaks": "pass" if not leak_findings else "fail",
    }
    if state is not None:
        checks["github"] = (
            "pass" if not remote_findings else "fail"
        )
    write_report(snapshot, policy, findings, checks)
    if output_format == "json":
        state_descriptor = -1
        try:
            state_descriptor, _ = _private_state_descriptor(
                root, create=False
            )
            body = _read_private_artifact(
                state_descriptor,
                "report.json",
                MAX_REPORT_BYTES,
            )
        finally:
            if state_descriptor >= 0:
                os.close(state_descriptor)
        sys.stdout.write(body.decode("ascii", "strict"))
    else:
        result = "pass" if not findings else "fail"
        print(f"result={result} findings={len(findings)}")
        if findings:
            print(render_findings(findings))
    if (
        state is not None
        and (
            state.visibility not in {"private", "public"}
            or remote_findings
        )
    ):
        return ExitCode.REMOTE_OR_PROTECTION
    if git_findings or leak_findings:
        return ExitCode.POLICY_OR_CONTENT
    return ExitCode.PASS


def _inspect_remote(root: Path, remote_name: str) -> ExitCode:
    policy = load_policy(
        root / ".public-repository-safety.json"
    )
    configured_url = _configured_push_remote(root, remote_name)
    if (
        github_repository_from_remote(configured_url)
        != policy.repository
    ):
        raise RemoteProtectionError(
            "intended remote does not match policy"
        )
    selected = select_public_refs(root, policy)
    snapshot = resolve_repository(root, selected, policy)
    state = inspect_github(snapshot, policy)
    if not state.complete:
        return ExitCode.INCOMPLETE_SURFACE
    if (
        state.visibility not in {"private", "public"}
        or state.findings
    ):
        return ExitCode.REMOTE_OR_PROTECTION
    return ExitCode.PASS


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "check-create":
            return (
                ExitCode.PASS
                if arguments.visibility == "private"
                else ExitCode.REMOTE_OR_PROTECTION
            )
        root = _canonical_repository_root(arguments.repo)
        if arguments.command == "approve":
            approve_report(
                root,
                arguments.report_digest,
                arguments.approval_id,
            )
            return ExitCode.PASS
        if arguments.command == "install-hook":
            install_hook(root)
            return ExitCode.PASS
        if arguments.command == "install-ci":
            install_ci(root)
            return ExitCode.PASS
        if arguments.command == "inspect-remote":
            return _inspect_remote(root, arguments.remote)
        return _audit_repository(
            root,
            arguments.remote,
            arguments.format,
            arguments.local_only,
        )
    except PolicyError:
        print("audit blocked: policy or content", file=sys.stderr)
        return ExitCode.POLICY_OR_CONTENT
    except ApprovalError:
        print("audit blocked: approval unavailable", file=sys.stderr)
        return ExitCode.APPROVAL
    except RemoteProtectionError:
        print(
            "audit blocked: remote or protection unsafe",
            file=sys.stderr,
        )
        return ExitCode.REMOTE_OR_PROTECTION
    except (
        ToolError,
        AuditInputError,
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
    ):
        print("audit blocked: tooling or input unavailable", file=sys.stderr)
        return ExitCode.TOOLING_OR_INPUT


if __name__ == "__main__":
    raise SystemExit(main())
