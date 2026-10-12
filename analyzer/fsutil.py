"""Output files describe your infrastructure: create them readable by the owner only.

Every output goes through :func:`write_private`: the folder is a real directory owned by you with mode 0700, and the
file is written to a fresh 0600 temporary file next to it and then renamed over the target. The rename never writes
through a symlink or hard link planted at the target name, a reader that opened the old file never sees the new
content, and a write that fails half-way leaves the previous file intact.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def data_home() -> Path:
    """Where outputs (``output/``) and user settings (``config/analyzer.toml``) live.

    ``AWS_ANALYZER_HOME`` wins. A copy installed as a Claude Code plugin lives in a cache folder that updates replace,
    so it keeps its data in ``~/aws-analyzer`` instead; a cloned repository keeps it next to the code, as before.
    """
    env = os.environ.get("AWS_ANALYZER_HOME", "").strip()
    if env:
        return Path(env).expanduser()
    if "/.claude/plugins/" in ROOT.as_posix() + "/":
        return Path.home() / "aws-analyzer"
    return ROOT


class UnsafeOutputPath(OSError):
    """The output folder or file is not something we can safely write private data into."""


def ensure_private_dir(directory: Path) -> Path:
    """Create ``directory`` (and any missing parents) with mode 0700, or tighten an existing one to 0700.

    An existing folder must be a real directory (not a symlink) owned by the current user; anything else is refused
    rather than written into.
    """
    directory = Path(directory)
    missing = []
    d = directory
    while not os.path.lexists(d):
        missing.append(d)
        if d.parent == d:
            break
        d = d.parent
    for d in reversed(missing):         # parents first; each created folder gets 0700, not just the leaf
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:         # created concurrently: checked below like any existing folder
            pass
        else:
            os.chmod(d, 0o700)          # mkdir's mode is filtered by the umask
    st = os.lstat(directory)
    if stat.S_ISLNK(st.st_mode):
        raise UnsafeOutputPath(f"output folder {directory} is a symlink; pass the real folder instead")
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafeOutputPath(f"output folder {directory} is not a directory")
    if st.st_uid != os.getuid():
        raise UnsafeOutputPath(f"output folder {directory} is owned by another user; choose a folder you own")
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(directory, 0o700)      # also tighten a folder that already existed with looser permissions
    return directory


def write_private(path: Path, text: str) -> None:
    """Atomically write ``text`` to ``path`` with mode 0600 inside a private (0700) folder.

    Refuses a target that is a symlink, not a regular file, or hard-linked elsewhere (``st_nlink > 1``).
    """
    path = Path(path)
    parent = ensure_private_dir(path.parent)
    _check_target(path)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=f".{path.name}.", suffix=".tmp")   # O_EXCL, mode 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        _check_target(path)             # os.replace never follows a symlink, so a race here cannot redirect the write
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _check_target(path: Path) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise UnsafeOutputPath(f"refusing to write {path}: it is a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise UnsafeOutputPath(f"refusing to write {path}: it is not a regular file")
    if st.st_nlink > 1:
        raise UnsafeOutputPath(f"refusing to write {path}: it is hard-linked elsewhere")
