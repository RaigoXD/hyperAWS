"""The ONLY module in this project allowed to run the ``aws`` executable.

Everything that talks to AWS goes through :class:`AwsCli`, which

1. refuses any (service, operation) not in ``allowlist.OPERATIONS`` *before* a
   process is started,
2. additionally requires a read verb and rejects credential/data-yielding calls,
3. rejects flags that this module controls (``--endpoint-url``, ``--profile`` ...,
   also abbreviated) and argument values the CLI would load from local files,
4. runs ``aws`` with an argv list (never a shell, no stdin) from a verified binary
   (AWS CLI v2, not inside the project or the current directory), in an
   environment that cannot redirect the requests, and never a command that
   ``~/.aws/cli/alias`` redefines; operations whose answer holds a secret only
   with a ``--query`` projection (``allowlist.QUERY_REQUIRED``),
5. re-checks the complete argv where the process is started, so the executor
   cannot be used to run anything :meth:`AwsCli.call` would refuse,
6. records every call in an audit log that ends up in the scan file and the
   HTML report.

``audit.py`` statically enforces that no other module imports ``subprocess``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # the one and only allowed use in the code base
import sys
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable

from . import allowlist
from .model import mask_identity

# --------------------------------------------------------------------------
# Errors


class ReadOnlyViolation(Exception):
    """Raised when code tries to run something that is not an allowed read."""


class UnsafeArgument(ReadOnlyViolation):
    """An argument VALUE that must not reach the CLI (it would load a local file, or it is malformed).

    Values are usually resource names or ids that came back from AWS, so a scan skips that one call and records a
    coverage gap (``scan.Ctx.aws``) instead of aborting. Everything else stays a fatal :class:`ReadOnlyViolation`:
    an operation that is not allowlisted, or a reserved flag, can only come from the code.
    """


class AwsCliError(Exception):
    def __init__(self, message: str, code: str = "Unknown", stderr: str = ""):
        super().__init__(message)
        self.code = code
        self.stderr = stderr


class AccessDenied(AwsCliError):
    """The principal lacks permission for this call."""


class NotAvailable(AwsCliError):
    """Service not enabled/subscribed in this region or account."""


class Throttled(AwsCliError):
    """Still throttled after our retries."""


class AuthError(AwsCliError):
    """No/expired credentials, or no usable aws binary. Fatal for the scan."""


_ERR_RE = re.compile(
    r"An error occurred \((?P<code>[A-Za-z0-9_.]+)\) when calling the "
    r"(?P<op>[A-Za-z0-9]+) operation[^:]*: (?P<msg>.*)",
    re.S,
)
_ACCESS_DENIED = {
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
    "UnauthorizedAccess", "AuthorizationError", "NotAuthorized",
    "OperationNotPermitted", "AccessDeniedFault", "ForbiddenException",
}
_NOT_AVAILABLE = {
    "OptInRequired", "SubscriptionRequiredException", "UnrecognizedClientException",
    "InvalidClientTokenId", "AuthFailure", "UnsupportedOperation",
    "InvalidAction", "ServiceUnavailableException",
}
_THROTTLE = {
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "TooManyRequestsException", "ProvisionedThroughputExceededException",
    "RequestThrottled", "SlowDown", "Throttled", "LimitExceededException",
}
_AUTH_HINTS = (
    "Unable to locate credentials",
    "ExpiredToken",
    "Token has expired",
    "SSO session associated with this profile has expired",
    "Error loading SSO Token",
    "The config profile",  # "(x) could not be found"
    "Enter MFA code",      # an assume-role profile that needs an MFA code nobody can type (stdin is closed)
)


def classify_error(stderr: str) -> AwsCliError:
    m = _ERR_RE.search(stderr)
    if m:
        code, msg = m.group("code"), m.group("msg").strip()
        if code in _ACCESS_DENIED:
            return AccessDenied(msg, code, stderr)
        if code in _THROTTLE:
            return Throttled(msg, code, stderr)
        if code in _NOT_AVAILABLE:
            return NotAvailable(msg, code, stderr)
        if code in ("ExpiredToken", "ExpiredTokenException"):
            return AuthError(msg, code, stderr)
        return AwsCliError(msg, code, stderr)
    if any(h in stderr for h in _AUTH_HINTS):
        return AuthError(stderr.strip().splitlines()[-1] if stderr.strip() else "auth error",
                         "AuthError", stderr)
    if "Could not connect to the endpoint URL" in stderr:
        return AwsCliError("could not connect to endpoint", "ConnectError", stderr)
    return AwsCliError(stderr.strip()[-300:] or "aws cli failed", "Unknown", stderr)


# --------------------------------------------------------------------------
# The guard (pure function: usable by tests, audit and the Claude hook)

# shorthand syntax (not JSON) loads a single value from a file when the key is written `Key@=file://...` (CLI v2)
_SHORTHAND_FROM_FILE = re.compile(r"@\s*=")


def check_command(service: str, op: str, args: Iterable[str] = ()) -> allowlist.Op:
    """Raise ReadOnlyViolation unless ``aws <service> <op> <args>`` is allowed.

    Callers pass every value that comes from data glued to its flag (``--table-name=<name>``): argparse then never
    reads the value as an option, and this guard checks the flag part and the value part separately. A bad value
    raises :class:`UnsafeArgument`, a reserved flag or an operation that is not allowlisted a plain ReadOnlyViolation.
    """
    args = list(args)
    if not re.fullmatch(r"[a-z0-9]+", service or ""):
        raise ReadOnlyViolation(f"invalid service name: {service!r}")
    if not re.fullmatch(r"[a-z0-9-]+", op or ""):
        raise ReadOnlyViolation(f"invalid operation name: {op!r}")
    if not allowlist.READ_VERB.match(op):
        raise ReadOnlyViolation(f"'{service} {op}' is not a read verb (describe/list/get)")
    if (service, op) in allowlist.DENY_EXACT or allowlist.DENY_OP.search(op):
        raise ReadOnlyViolation(f"'{service} {op}' is on the deny list (credentials/secrets/data)")
    entry = allowlist.ALLOWED.get((service, op))
    if entry is None:
        raise ReadOnlyViolation(f"'{service} {op}' is not in the allowlist (analyzer/allowlist.py)")
    for a in args:
        _check_arg(a)
    return entry


def _check_arg(a: Any) -> None:
    if not isinstance(a, str):
        raise ReadOnlyViolation(f"non-string argument: {a!r}")
    value = a
    if a.startswith("--"):
        flag, sep, value = a.partition("=")
        if flag == "--":
            raise ReadOnlyViolation("a bare '--' would end option parsing (and hide the flags awscli.py appends)")
        if "\x00" in flag:
            raise ReadOnlyViolation("NUL byte in a flag")
        if _is_forbidden_flag(flag):
            raise ReadOnlyViolation(f"flag {flag} is controlled by awscli.py and may not be passed")
        if not sep:
            return
    _check_value(value)


def _check_value(value: str) -> None:
    """A value (a separate token, or the part after '=' of ``--flag=value``) must reach AWS verbatim."""
    if "\x00" in value:
        raise UnsafeArgument("NUL byte in argument")
    v = value.lstrip().lower()
    if v.startswith(allowlist.LOCAL_FILE_PREFIXES):
        raise UnsafeArgument("file:// and fileb:// values would make the AWS CLI read local files")
    if (not v.startswith(("[", "{")) and _SHORTHAND_FROM_FILE.search(v)
            and any(p in v for p in allowlist.LOCAL_FILE_PREFIXES)):
        raise UnsafeArgument("shorthand Key@=file://... would make the AWS CLI read a local file")


def _is_forbidden_flag(flag: str) -> bool:
    """Exact match OR any prefix of one: the AWS CLI's argparse expands every unambiguous prefix (--e is --endpoint-url)."""
    return any(f.startswith(flag) for f in allowlist.FORBIDDEN_FLAGS)


def _check_projection(service: str, op: str, args: list[str]) -> None:
    """An operation in allowlist.QUERY_REQUIRED answers with a secret field unless a --query projection drops it."""
    if (service, op) in allowlist.QUERY_REQUIRED and not any(
            (a == "--query" and i + 1 < len(args)) or a.startswith("--query=") for i, a in enumerate(args)):
        raise ReadOnlyViolation(f"'{service} {op}' answers with secret fields; call it with a --query projection "
                                "(allowlist.QUERY_REQUIRED)")


# --------------------------------------------------------------------------
# ~/.aws/cli/alias: the AWS CLI lets an alias redefine ANY command, also `sts` or `ec2 describe-instances` (and a
# `!` alias runs a shell command), so a command this module runs must not be one. The hook shares the parser.

_ALIAS_FILE: str | None = None     # None: <HOME>/.aws/cli/alias, where the aws process looks (tests point it elsewhere)


def alias_names(text: str) -> set[tuple[str, str]]:
    """(section, name) pairs of an AWS CLI alias file (INI: ``[toplevel]``, ``[command ec2]``, ``name = value``).

    Section and alias names are compared in lower case and with single spaces (stricter than the CLI). Raises
    ValueError for text that is not such a file (the caller then refuses: fail closed)."""
    names, section = set(), None
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "#;" or (line[:1] in " \t" and section is not None):
            continue                                      # blank, comment, continuation of a multi-line value
        m = re.fullmatch(r"\[([^\]]+)\]", s)
        if m:
            section = " ".join(m.group(1).split()).lower()
            continue
        name = re.split(r"[=:]", s, maxsplit=1)
        if section is None or len(name) < 2:
            raise ValueError("not an alias file")
        names.add((section, name[0].strip().lower()))
    return names


def _alias_file(env: dict[str, str]) -> str:
    """The alias file the aws process will read: ``~/.aws/cli/alias`` expanded with the HOME it gets."""
    if _ALIAS_FILE is not None:
        return _ALIAS_FILE
    home = env.get("HOME")
    if home is None:
        try:
            import pwd  # POSIX only; what Python's expanduser falls back to without HOME
            home = pwd.getpwuid(os.getuid()).pw_dir
        except (ImportError, KeyError):
            home = os.path.expanduser("~")
    if os.sep != "/":
        return os.path.join(home, ".aws", "cli", "alias")
    return home.rstrip("/") + "/.aws/cli/alias"           # exactly what os.path.expanduser("~/.aws/cli/alias") gives


def _alias_problem(env: dict[str, str], commands: Iterable[tuple[str, str]]) -> str | None:
    """Why the alias file makes one of ``commands`` ((service, op) pairs) something else, or None."""
    path = _alias_file(env)
    try:
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8", errors="replace") as f:
            names = alias_names(f.read())
    except (OSError, ValueError) as e:
        return f"the AWS CLI alias file {path} could not be read ({type(e).__name__}), so any aws command may be redefined"
    hits = sorted({f"aws {s}" for s, _ in commands if ("toplevel", s) in names}
                  | {f"aws {s} {o}" for s, o in commands if (f"command {s}", o) in names})
    if hits:
        return (f"the AWS CLI alias file {path} redefines {', '.join(hits[:5])}{' ...' if len(hits) > 5 else ''}; "
                "remove or rename those aliases (an alias can run another command or a shell command)")
    return None


def _our_commands() -> set[tuple[str, str]]:
    """Every (service, op) this module may run, including the local `configure list-profiles`."""
    return set(allowlist.ALLOWED) | {tuple(c) for c in _LOCAL_COMMANDS if len(c) == 2}


# --------------------------------------------------------------------------
# Audit log

def redact(text: str) -> str:
    """Mask access-key-like tokens (AKIA…, also in ``x_AKIA…``) and e-mail local parts (``j…@corp.example``, e.g. an
    SSO session name in the caller ARN or an AccessDenied message) before anything is logged or saved."""
    return mask_identity(text)


@dataclass
class CallRecord:
    ts: float
    profile: str | None
    service: str
    op: str
    region: str | None
    args: str
    status: str  # ok | empty | denied | unavailable | throttled | error | planned | refused
    ms: int
    code: str | None = None

    def as_dict(self) -> dict:
        d = asdict(self)
        d["ts"] = round(self.ts, 3)
        return d


# --------------------------------------------------------------------------
# The aws binary and the one place a process is started

Executor = Callable[[list[str], dict[str, str], float], "tuple[int, str, str]"]

# appended by AwsCli.call after the caller's arguments (and checked again by _recheck_argv)
_OWN_FLAGS = ("--output", "json", "--no-cli-pager", "--cli-read-timeout", "60", "--cli-connect-timeout", "10")
# region names come from data too (describe-regions, S3 BucketRegion): letters, digits, single hyphens
_REGION = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_LOCAL_COMMANDS = (["--version"], ["configure", "list-profiles"])   # the two fixed local (non-API) commands

AWS_BIN_ENV = "AWS_ANALYZER_AWS_BIN"   # optional: absolute path of the aws binary to use instead of a PATH lookup
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
_TRUSTED_BINS: set[str] = set()        # aws binaries that passed resolve_aws_bin() (the paths that are executed)
_TRUSTED_LOCK = threading.Lock()
_VERSION = re.compile(r"aws-cli/(\d+)\.\S+")

# Never inherited by the aws process: AWS_CA_BUNDLE is the environment twin of the forbidden --ca-bundle flag,
# AWS_DATA_PATH adds API model folders (a crafted model could map a read command to a write API), and
# AWS_PROFILE because --profile is always passed explicitly.
_DROPPED_ENV = ("AWS_CA_BUNDLE", "AWS_DATA_PATH", "AWS_PROFILE")
# Inherited, but recorded in the scan when set: they decide where requests go and which config is read.
_NOTED_ENV = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy",
              "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE")


def _build_argv(aws_bin: str, service: str, op: str, args: list[str], region: str | None,
                profile: str | None) -> list[str]:
    argv = [aws_bin, service, op, *args, *_OWN_FLAGS]
    if region:
        argv.append(f"--region={region}")     # glued: a value can never be read as another flag
    if profile:
        argv.append(f"--profile={profile}")
    return argv


def _recheck_argv(argv: Any) -> None:
    """Validate a complete argv again where the process starts (raises ReadOnlyViolation).

    Accepts exactly what AwsCli builds: a verified aws binary running one of the two local commands, or
    ``<service> <op> <guarded args> <own flags> [--region=R] [--profile=P]``. So calling the executor directly
    (``_subprocess_executor``, ``AwsCli._executor``) cannot run anything :meth:`AwsCli.call` would refuse.
    """
    if not (isinstance(argv, list) and len(argv) >= 2 and all(isinstance(a, str) for a in argv)):
        raise ReadOnlyViolation("malformed argv")
    exe, rest = argv[0], argv[1:]
    if rest == ["--version"] and os.path.basename(exe) == "aws" and _bin_location_problem(exe) is None:
        return                                      # the probe that verifies a binary before it is trusted
    with _TRUSTED_LOCK:
        trusted = exe in _TRUSTED_BINS
    if not trusted:
        raise ReadOnlyViolation(f"{exe!r} is not the verified aws binary")
    if rest in _LOCAL_COMMANDS:
        return
    if len(rest) < 2 or "--output" not in rest[2:]:
        raise ReadOnlyViolation("argv was not built by AwsCli.call")
    service, op, tail = rest[0], rest[1], rest[2:]
    i = tail.index("--output")                      # check_command refuses --output in the caller's arguments
    args, own = tail[:i], tail[i:]
    if tuple(own[:len(_OWN_FLAGS)]) != _OWN_FLAGS:
        raise ReadOnlyViolation("argv was not built by AwsCli.call")
    extra = own[len(_OWN_FLAGS):]
    if extra and extra[0].startswith("--region="):
        if not _REGION.fullmatch(extra.pop(0)[len("--region="):]):
            raise ReadOnlyViolation("invalid region in argv")
    if extra and extra[0].startswith("--profile="):
        if not _valid_profile(extra.pop(0)[len("--profile="):]):
            raise ReadOnlyViolation("invalid profile in argv")
    if extra:
        raise ReadOnlyViolation(f"unexpected trailing arguments: {extra!r}")
    check_command(service, op, args)
    _check_projection(service, op, args)


def _valid_profile(profile: str) -> bool:
    return bool(profile) and "\x00" not in profile


def _subprocess_executor(argv: list[str], env: dict[str, str], timeout: float):
    """Start ``aws``: the only process this code base starts. The argv is re-checked first (see _recheck_argv), and
    the alias file must not redefine the command (read again for every process, so a later edit is seen too)."""
    _recheck_argv(argv)
    if argv[1:] != ["--version"]:
        problem = _alias_problem(env, [(argv[1], argv[2])])
        if problem:
            raise AuthError(f"refusing to run aws: {problem}", "AwsCliRefused")
    try:
        p = subprocess.run(  # noqa: S603 - argv list, shell=False, guarded above
            argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, shell=False
        )
    except subprocess.TimeoutExpired:
        return 124, "", "An error occurred (RequestTimeout) when calling the Op operation: timed out"
    return p.returncode, p.stdout, p.stderr


def _clean_env() -> dict[str, str]:
    env = {
        k: v for k, v in os.environ.items()
        # never let the environment redirect signed requests to another host
        if not (k == "AWS_ENDPOINT_URL" or k.startswith("AWS_ENDPOINT_URL_")) and k not in _DROPPED_ENV
    }
    # ... nor the config file: endpoint_url in a [profile] or [services] section (any AWS_CONFIG_FILE) is ignored
    env["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "true"
    env["AWS_CLI_AUTO_PROMPT"] = "off"   # never prompt (stdin is closed as well)
    env["AWS_PAGER"] = ""
    env["AWS_RETRY_MODE"] = "standard"
    env["AWS_MAX_ATTEMPTS"] = "5"
    env["AWS_DEFAULT_OUTPUT"] = "json"
    return env


def _norm(path: str) -> str:
    return path.lower() if sys.platform == "darwin" else path   # macOS volumes are case-insensitive by default


def _inside(path: str, folder: str) -> bool:
    path, folder = _norm(path), _norm(folder.rstrip(os.sep) or os.sep)
    return path == folder or path.startswith(folder if folder.endswith(os.sep) else folder + os.sep)


_TEMP_DIRS = ("/tmp", "/var/tmp", "/var/folders", "/dev/shm")


def _workspace(cwd: str, home: str) -> bool:
    """Is ``cwd`` where untrusted files usually live (a cloned repository, an unpacked download): a folder below the
    home folder or in a temporary folder? System folders such as /usr/local or /opt are not."""
    temps = {os.path.realpath(t) for t in (*_TEMP_DIRS, os.environ.get("TMPDIR") or "/tmp")}
    return (_inside(cwd, home) and _norm(cwd) != _norm(home)) or any(_inside(cwd, t) for t in temps)


def _bin_location_problem(path: str) -> str | None:
    """Why the aws binary at ``path`` must not be run (a planted `aws` would see every request), or None."""
    if not os.path.isabs(path):
        return "it was found through a relative PATH entry (relative to the current directory)"
    try:
        cwd = os.path.realpath(os.getcwd())
    except OSError:
        cwd = None
    home = os.path.realpath(os.path.expanduser("~"))
    for p in {os.path.abspath(path), os.path.realpath(path)}:
        if _inside(p, PROJECT_DIR):
            return f"it lives inside the analyzer's own folder ({PROJECT_DIR})"
        # In the current directory itself, or below it when that is a workspace (`./bin/aws`, `node_modules/.bin/aws`
        # or `.venv/bin/aws` of a repository). Running from a system folder above a normal install (/usr/local for
        # /usr/local/bin/aws, /opt for /opt/homebrew/bin/aws) or from the home folder (~/.local/bin/aws) is fine.
        in_cwd = cwd and _norm(os.path.dirname(p)) == _norm(cwd)
        below_cwd = cwd and _inside(p, cwd) and _workspace(cwd, home)
        if in_cwd or below_cwd:
            return f"it lives in the current directory ({cwd}); run the analyzer from another directory"
    return None


def _owner(path: str) -> str | None:
    try:
        uid = os.stat(path).st_uid
    except OSError:
        return None
    try:
        import pwd  # POSIX only
        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        return str(uid)


def resolve_aws_bin(env: dict[str, str]) -> dict:
    """Find, check and verify the aws binary once. Returns what the scan records about it.

    Raises :class:`AuthError` (fatal, with a clear message) when there is none or it must not be run: found
    through a relative PATH entry or inside the project or current directory (PATH hijack), not named ``aws``, or
    not AWS CLI v2 (v1 parses arguments differently from what the guard models).
    """
    pinned = os.environ.get(AWS_BIN_ENV)
    found = pinned or shutil.which("aws")
    if not found:
        raise AuthError("the 'aws' CLI was not found on PATH", "NoAwsCli")
    if pinned and not os.path.isabs(pinned):
        raise AuthError(f"refusing to run {pinned}: {AWS_BIN_ENV} must be an absolute path", "AwsCliRefused")
    problem = _bin_location_problem(found) or (None if os.path.basename(found) == "aws" else "it is not named aws")
    if problem:
        raise AuthError(f"refusing to run {found}: {problem}", "AwsCliRefused")
    path, real = os.path.abspath(found), os.path.realpath(found)
    rc, out, err = _subprocess_executor([path, "--version"], env, 30)
    text = (out or err).strip()
    m = _VERSION.match(text)
    if rc != 0 or not m:
        raise AuthError(f"refusing to run {path}: could not read its version ({text[:80]!r})", "AwsCliRefused")
    if int(m.group(1)) < 2:
        raise AuthError(f"refusing to run {path}: {m.group(0)} is AWS CLI v1; install AWS CLI v2", "AwsCliRefused")
    problem = _alias_problem(env, _our_commands())          # checked again before every process (_subprocess_executor)
    if problem:
        raise AuthError(f"refusing to run {path}: {problem}", "AwsCliRefused")
    notes = []
    try:
        if os.stat(real).st_uid != 0:
            notes.append("the binary is not owned by root")
    except OSError:
        pass
    for d in sorted({os.path.dirname(path), os.path.dirname(real)}):
        if os.access(d, os.W_OK):
            notes.append(f"{d} is writable by the current user")
    with _TRUSTED_LOCK:
        _TRUSTED_BINS.add(path)
    return {
        "path": path, "real_path": real, "version": m.group(0), "owner": _owner(real), "verified": True,
        "pinned": bool(pinned), "notes": notes,
        # names only (proxy URLs can carry passwords)
        "environment": [f"{k} is set" for k in _NOTED_ENV if os.environ.get(k)]
                       + [f"{k} is set but not passed to aws" for k in ("AWS_CA_BUNDLE", "AWS_DATA_PATH") if os.environ.get(k)],
    }


class AwsCli:
    """Guarded, audited, thread-safe wrapper around ``aws``."""

    def __init__(
        self,
        profile: str | None = None,
        *,
        executor: Executor | None = None,
        aws_bin: str | None = None,
        dry_run: bool = False,
        max_procs: int = 12,
        timeout: float = 300.0,
        throttle_retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if aws_bin is not None and executor is None:
            raise ValueError("aws_bin is only for a test/demo executor: the real aws binary is always resolved and "
                             f"verified (pin it with {AWS_BIN_ENV}=/absolute/path/aws)")
        self.profile = profile
        self.dry_run = dry_run
        self.timeout = timeout
        self.throttle_retries = throttle_retries
        self._executor = executor or _subprocess_executor
        self._offline = executor is not None          # tests and the demo: no aws process is ever started
        # shared (by reference) with every with_profile() sibling: the binary is resolved once per run
        self._bin_info: dict = {"path": aws_bin or "aws"} if self._offline else {}
        self._bin_lock = threading.Lock()
        self._sem = threading.BoundedSemaphore(max_procs)
        self._lock = threading.Lock()
        self._log: list[CallRecord] = []
        self._sleep = sleep
        self._env = _clean_env()

    # -- helpers --------------------------------------------------------
    def _bin(self) -> str:
        with self._bin_lock:
            if "verified" not in self._bin_info:
                if self._offline:
                    self._bin_info.update(version=None, verified=False,
                                          notes=["offline executor (tests or demo): no aws process is started"])
                else:
                    self._bin_info.update(resolve_aws_bin(self._env))
            return self._bin_info["path"]

    def binary_info(self) -> dict:
        """Path, version, owner and notes of the aws binary (recorded in the scan). A dry run starts no process."""
        if self.dry_run and not self._offline and "verified" not in self._bin_info:
            return {"path": None, "version": None, "verified": False, "notes": ["dry run: the aws binary was not run"]}
        self._bin()
        with self._bin_lock:
            return json.loads(json.dumps(self._bin_info))

    def _record(self, rec: CallRecord) -> None:
        with self._lock:
            self._log.append(rec)

    def audit_log(self) -> list[dict]:
        with self._lock:
            return [r.as_dict() for r in self._log]

    def with_profile(self, profile: str | None) -> "AwsCli":
        """A sibling client for another profile sharing executor, binary and audit log."""
        other = AwsCli.__new__(AwsCli)
        other.__dict__.update(self.__dict__)
        other.profile = profile
        return other

    # -- the one entry point for API calls ------------------------------
    def call(
        self,
        service: str,
        op: str,
        args: Iterable[str] = (),
        *,
        region: str | None = None,
        expect: Iterable[str] = (),
        default: Any = None,
    ) -> Any:
        """Run ``aws <service> <op> <args>`` and return the parsed JSON.

        ``expect`` lists error codes that simply mean "nothing there" (e.g.
        NoSuchLifecycleConfiguration): the call returns ``default`` instead of
        raising. Any other failure raises an :class:`AwsCliError` subclass.
        """
        args = list(args)
        try:
            check_command(service, op, args)  # <-- raises ReadOnlyViolation
            _check_projection(service, op, args)
            if region and not self.dry_run and not _REGION.fullmatch(region):
                raise UnsafeArgument(f"invalid region name {region[:40]!r}")
            if self.profile is not None and not _valid_profile(self.profile):
                raise ReadOnlyViolation(f"invalid profile name {self.profile[:40]!r}")
        except UnsafeArgument:   # a data value was refused: visible in the audit log, no process started
            self._record(CallRecord(time.time(), self.profile, service, op, region,
                                    redact(" ".join(map(str, args)))[:200], "refused", 0, "UnsafeArgument"))
            raise
        expect = set(expect)
        shown = redact(" ".join(args))[:200]
        if self.dry_run:
            self._record(CallRecord(time.time(), self.profile, service, op, region, shown, "planned", 0))
            return default if default is not None else {}

        argv = _build_argv(self._bin(), service, op, args, region, self.profile)

        attempt = 0
        while True:
            t0 = time.time()
            with self._sem:
                rc, out, err = self._executor(argv, self._env, self.timeout)
            ms = int((time.time() - t0) * 1000)
            if rc == 0:
                try:
                    data = json.loads(out) if out.strip() else {}
                except json.JSONDecodeError as e:
                    self._record(CallRecord(t0, self.profile, service, op, region, shown, "error", ms, "BadJson"))
                    raise AwsCliError(f"invalid JSON from aws cli: {e}", "BadJson", err) from e
                self._record(CallRecord(t0, self.profile, service, op, region, shown, "ok", ms))
                return data
            exc = classify_error(err)
            if exc.code in expect:
                self._record(CallRecord(t0, self.profile, service, op, region, shown, "empty", ms, exc.code))
                return default
            if isinstance(exc, Throttled) and attempt < self.throttle_retries:
                attempt += 1
                self._sleep(min(30.0, 2.0 ** attempt))
                continue
            status = {AccessDenied: "denied", NotAvailable: "unavailable", Throttled: "throttled"}.get(type(exc), "error")
            self._record(CallRecord(t0, self.profile, service, op, region, shown, status, ms, exc.code))
            raise exc

    # -- two fixed local (non-API) commands ------------------------------
    def local_profiles(self) -> list[str]:
        """Profile names from local config (`aws configure list-profiles`; no API call)."""
        rc, out, _ = self._executor([self._bin(), "configure", "list-profiles"], self._env, 30)
        return [ln.strip() for ln in out.splitlines() if ln.strip()] if rc == 0 else []

    def cli_version(self) -> str:
        """``aws-cli/2.x.y (/path/to/aws)`` for the verified binary (resolving it, which refuses AWS CLI v1)."""
        info = self.binary_info()
        if info.get("verified"):
            return f"{info['version']} ({info['path']})"
        rc, out, err = self._executor([self._bin(), "--version"], self._env, 30)
        return (out or err).strip().split()[0] if rc == 0 and (out or err).strip() else "unknown"
