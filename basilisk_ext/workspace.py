"""
workspace — import a repo as a zip, work on it whole, export it back.

The job: the operator hands over a .zip of a repo, Basilisk unpacks it into a
private working tree, reads and edits ANY file in it, runs the project's own
tests, and zips the result back out for him to drop over his checkout.

Same contract as the rest of basilisk_ext: imports NOTHING from the Basilisk
core, pure stdlib, writes no exploit code.  It does not execute anything
itself -- running the project's tests goes through the core's existing
tool_run_command, which means the destructive-command floor and the scope
gate still apply unchanged.  This module owns exactly one new boundary, and
it is a filesystem one.

═══════════════════════════════════════════════════════════════════════
THE CONTAINMENT BOUNDARY
═══════════════════════════════════════════════════════════════════════
Every path this module touches is resolved and then checked to be INSIDE
the active workspace root.  That check is `_confine()`, it is called by
every read, write, move and delete, and it FAILS CLOSED.

Why this is not paranoia about a hypothetical:

  1. ZIP SLIP.  A zip entry named "../../.ssh/authorized_keys" extracts
     outside the destination directory on a naive extractall().  This is
     CVE-2007-4559 and it was still live in Python's own tarfile in 2022.
     The operator will be feeding this module zips, and a repo zip is
     exactly the kind of file that gets forwarded around before it lands.

  2. SYMLINK ESCAPE.  A zip can carry a symlink entry `docs -> /` and then
     a regular entry `docs/etc/passwd`.  Extraction follows the link and
     writes outside the tree.  Rejecting `..` alone does NOT catch this.

  3. THE AGENT ITSELF.  Basilisk is autonomous under UNLEASH.  A model that
     decides "the fix belongs in ~/.bashrc" is not misbehaving in any way
     the model can detect -- it is one wrong path away from editing the
     operator's home directory instead of his repo.  A boundary that exists
     only in the prompt is a suggestion.

`_confine()` resolves symlinks with os.path.realpath BEFORE comparing, and
compares with os.path.commonpath rather than str.startswith -- because
"/home/u/repo-evil" startswith "/home/u/repo" is True, and that is a
containment bypass sitting in one operator convenience.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
  · It does not run anything.  Tests run through the core's gated executor.
  · It does not touch git.  The operator's history is his; this hands back
    a zip and he does the diffing with tools he already trusts.
  · It does not write outside the workspace, ever, including the export --
    the export lands inside the workspace's own parent, under DATA_DIR.
"""

from __future__ import annotations

import ast
import difflib
import fnmatch
import io
import json
import os
import re
import shutil
import stat
import threading
import time
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── limits ───────────────────────────────────────────────────────────
# These are not tuning knobs, they are the zip-bomb floor.  A 42 KB zip can
# decompress to petabytes; without a budget the extract is a denial of
# service on the operator's own disk.
MAX_ZIP_BYTES = 512 * 1024 * 1024      # refuse an archive bigger than this
MAX_TOTAL_UNPACKED = 2 * 1024 * 1024 * 1024   # 2 GB of expanded content
MAX_FILES = 40_000
MAX_RATIO = 200                        # per-entry compression ratio ceiling
MAX_EDIT_BYTES = 8 * 1024 * 1024       # single-file write ceiling

# Directories that are never worth reading, indexing, or shipping back.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".venv", "venv", "env", "node_modules",
    ".idea", ".vscode", "dist", "build", ".next", ".nuxt", "target",
    ".gradle", ".terraform", "vendor", ".DS_Store", ".eggs",
}
SKIP_SUFFIXES = {
    ".pyc", ".pyo", ".class", ".o", ".so", ".dylib", ".dll", ".exe",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".pdf", ".woff", ".woff2",
    ".ttf", ".eot", ".db", ".sqlite", ".sqlite3", ".bin", ".dat",
}

# Files that must never leave the operator's machine inside an export, and
# that Basilisk should not be reading into a cloud model's context either.
# A repo zip routinely carries a stray .env; the model does not need it and
# the provider definitely does not.
SECRET_NAMES = {
    ".env", ".env.local", ".env.production", ".netrc", ".pgpass",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials",
    "secrets.json", "settings.json",
}
SECRET_SUFFIXES = {".pem", ".key", ".pfx", ".p12", ".keystore", ".jks"}

LANG_BY_SUFFIX = {
    ".py": "python", ".pyi": "python", ".js": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin",
    ".rb": "ruby", ".php": "php", ".c": "c", ".h": "c", ".cpp": "cpp",
    ".hpp": "cpp", ".cs": "csharp", ".swift": "swift", ".sh": "shell",
    ".bash": "shell", ".zsh": "shell", ".sql": "sql", ".html": "html",
    ".css": "css", ".scss": "css", ".md": "markdown", ".rst": "markdown",
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "toml",
    ".ini": "ini", ".cfg": "ini", ".xml": "xml", ".vue": "vue",
}


def _log(msg: str) -> None:
    print(f"[workspace] {msg}", flush=True)


# ═════════════════════════════════════════════════════════════════════
# CONTAINMENT
# ═════════════════════════════════════════════════════════════════════

class ContainmentError(Exception):
    """A path resolved outside the workspace root.  Always fatal to the op."""


def _confine(root: str, candidate: str) -> str:
    """Resolve `candidate` under `root` and REFUSE if it lands outside.

    Returns the absolute real path on success; raises ContainmentError
    otherwise.  This is the single choke point -- every filesystem
    operation in this module goes through it, so there is one place to
    audit and one place a bypass could hide.

    Three properties, each of which has been a real CVE class:

      · realpath BEFORE comparing, so a symlink inside the tree pointing
        out of it is caught.  Checking the literal string first and
        resolving later is the bug in most naive implementations.
      · commonpath, NOT startswith.  "/home/u/repo-old" starts with
        "/home/u/repo" but is a different directory.
      · absolute candidates are rejected outright rather than silently
        re-rooted, because silently re-rooting "/etc/passwd" to
        "<root>/etc/passwd" turns an obvious error into a confusing one.
    """
    if not root:
        raise ContainmentError("no active workspace")
    real_root = os.path.realpath(root)
    cand = candidate or "."
    # EXPAND ~ FIRST. Without this, "~/.bashrc" is not an escape -- it is
    # worse: os.path.join treats "~" as an ordinary directory name and
    # happily creates "<root>/~/.bashrc". Contained, so the boundary held,
    # but the operator asked to touch his shell config and got a junk
    # directory named "~" in his repo instead of an error. Expanding first
    # makes it absolute, which the check below then refuses out loud.
    cand = os.path.expanduser(cand)
    if os.path.isabs(cand):
        # Allow an absolute path only if it is already inside the root --
        # the model does sometimes echo back a full path we gave it.
        target = os.path.realpath(cand)
    else:
        target = os.path.realpath(os.path.join(real_root, cand))
    try:
        if os.path.commonpath([real_root, target]) != real_root:
            raise ContainmentError(
                f"path escapes the workspace: {candidate!r}")
    except ValueError:
        # commonpath raises on different drives / mixed absolute-relative.
        raise ContainmentError(f"path escapes the workspace: {candidate!r}")
    return target


def _is_secret(rel: str) -> bool:
    name = os.path.basename(rel)
    if name in SECRET_NAMES:
        return True
    return any(name.endswith(s) for s in SECRET_SUFFIXES)


def _skip_path(rel: str) -> bool:
    parts = Path(rel).parts
    if any(p in SKIP_DIRS for p in parts):
        return True
    return Path(rel).suffix.lower() in SKIP_SUFFIXES


# ═════════════════════════════════════════════════════════════════════
# STATE
# ═════════════════════════════════════════════════════════════════════

@dataclass
class WorkspaceState:
    name: str = ""
    root: str = ""
    source_zip: str = ""
    imported_at: float = 0.0
    file_count: int = 0
    total_bytes: int = 0
    # rel_path -> original sha-free marker; we keep the ORIGINAL bytes of
    # every file we modify so a revert never needs the source zip again
    # (the operator may well have deleted it).
    modified: List[str] = field(default_factory=list)
    created: List[str] = field(default_factory=list)
    deleted: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    # Edits made since the last workspace_verify, and the verdict that run
    # returned.  These drive the export gate below.
    edits_since_verify: int = 0
    last_verdict: str = ""
    verify_count: int = 0


_STATE = WorkspaceState()
_BASE_DIR: Optional[Path] = None

# Tool calls run on WORKER THREADS. Every mutating op below is a
# read-modify-write over both the filesystem and _STATE, and both halves
# race:
#
#   · _stash_original() is check-then-act ("if the original exists, return",
#     then copy). shutil.copy2 releases the GIL during I/O, so two threads
#     editing the same file can BOTH pass the check and the second one
#     stashes the ALREADY-EDITED content as the "original". revert() then
#     restores a modified file and the operator's true baseline is gone,
#     silently — the worst class of bug this module could have, because the
#     undo button is exactly what he reaches for when something went wrong.
#   · _mark() is `if rel not in lst: lst.append(rel)` — the same
#     check-then-act, producing duplicate entries in the change list.
#
# This is the identical shape to the engage.py loot race fixed in v7.9.1,
# where 120 concurrent records landed 1 of 60. That one did not look
# reproducible either until it was measured. An RLock across the whole
# stash → write → mark sequence closes both; it is reentrant because
# revert() marks while already holding it.
_LOCK = threading.RLock()


def configure(base_dir: str) -> None:
    """Point the module at a writable base (the core passes DATA_DIR).

    Kept as an explicit call rather than an import-time constant so this
    module stays importable and testable without the core present.
    """
    global _BASE_DIR
    _BASE_DIR = Path(base_dir) / "workspaces"
    _BASE_DIR.mkdir(parents=True, exist_ok=True)


def _base() -> Path:
    if _BASE_DIR is None:
        configure(os.path.expanduser("~/.local/share/basilisk"))
    return _BASE_DIR  # type: ignore[return-value]


def _orig_dir() -> Path:
    """Where pre-edit copies live.  Sibling of the tree, not inside it, so
    the originals never end up in the export."""
    return Path(_STATE.root).parent / "_originals"


def _require() -> str:
    if not _STATE.root or not os.path.isdir(_STATE.root):
        # SAY WHAT WOULD FIX IT, AND SAY IT ACCURATELY. This message read
        # "import a repo zip first", so a model holding a DIRECTORY path went
        # looking for a way to zip it — which is the exact friction
        # tool_workspace_import's docstring records as already fixed, leaking
        # back in through an error string nobody updated.
        raise ContainmentError(
            "no workspace open. Call workspace_import with the repo's "
            "path — a directory or a .zip, either works — then retry")
    return _STATE.root


# ═════════════════════════════════════════════════════════════════════
# IMPORT
# ═════════════════════════════════════════════════════════════════════

def _safe_members(zf: zipfile.ZipFile, dest: str) -> Tuple[List[zipfile.ZipInfo], List[str]]:
    """Filter a zip's members down to the ones that are safe to extract.

    Returns (accepted, rejected_descriptions).  Rejection reasons are kept
    and surfaced to the operator rather than silently dropped -- if his repo
    zip contains something this refuses, he needs to know which file and
    why, or he will think the import merely lost data.
    """
    accepted: List[zipfile.ZipInfo] = []
    rejected: List[str] = []
    total = 0
    real_dest = os.path.realpath(dest)

    for info in zf.infolist():
        name = info.filename

        # Directory entries are fine; we create dirs ourselves anyway.
        if name.endswith("/"):
            continue

        # ZIP SLIP.  Normalise and confirm the join stays under dest.  Note
        # this checks the DECLARED name, before anything is written -- we
        # never create the file and then ask where it went.
        norm = os.path.normpath(os.path.join(real_dest, name))
        try:
            if os.path.commonpath([real_dest, norm]) != real_dest:
                rejected.append(f"{name} (escapes destination — zip slip)")
                continue
        except ValueError:
            rejected.append(f"{name} (unresolvable path)")
            continue
        if os.path.isabs(name) or name.startswith("/") or ".." in Path(name).parts:
            rejected.append(f"{name} (absolute or parent-relative path)")
            continue

        # SYMLINK ENTRIES.  A zip stores the link target as the file body,
        # so extracting one creates a link we would then follow on the next
        # write.  Rejecting `..` does not catch `docs -> /`.
        #
        # CAREFUL WITH THE MODE BITS.  external_attr >> 16 is only a unix
        # mode when the archive was written by a unix tool. Zips written by
        # Windows, and by Python's own writestr(), carry permission bits
        # with NO file-type bits at all -- so S_ISREG() is False for a
        # perfectly ordinary file. Testing `not S_ISREG(mode)` therefore
        # rejects the entire contents of a normal archive, which is a
        # fail-CLOSED bug but a total one: nothing imports. Only judge the
        # type when the type field is actually populated.
        mode = info.external_attr >> 16
        fmt = stat.S_IFMT(mode)
        if fmt == stat.S_IFLNK:
            rejected.append(f"{name} (symlink entry)")
            continue
        if fmt not in (0, stat.S_IFREG):
            rejected.append(f"{name} (not a regular file)")
            continue

        # ZIP BOMB.  Per-entry ratio plus a running total.
        if info.compress_size > 0:
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > MAX_RATIO and info.file_size > 1_000_000:
                rejected.append(
                    f"{name} (compression ratio {ratio:.0f}:1 — refusing)")
                continue
        total += info.file_size
        if total > MAX_TOTAL_UNPACKED:
            rejected.append(f"{name} (total unpacked size cap reached)")
            break
        if len(accepted) >= MAX_FILES:
            rejected.append(f"{name} (file-count cap {MAX_FILES} reached)")
            break

        accepted.append(info)

    return accepted, rejected


def import_zip(zip_path: str, name: str = "") -> Dict[str, Any]:
    """Unpack a repo zip into a fresh workspace and make it active."""
    try:
        src = os.path.realpath(os.path.expanduser(zip_path))
        if not os.path.isfile(src):
            return {"ok": False, "error": f"no such file: {zip_path}"}
        size = os.path.getsize(src)
        if size > MAX_ZIP_BYTES:
            return {"ok": False,
                    "error": f"archive is {size / 1e6:.0f} MB, over the "
                             f"{MAX_ZIP_BYTES / 1e6:.0f} MB limit"}
        if not zipfile.is_zipfile(src):
            return {"ok": False, "error": f"not a zip archive: {zip_path}"}

        slug = re.sub(r"[^A-Za-z0-9._-]+", "-",
                      name or Path(src).stem).strip("-") or "repo"
        root = _base() / f"{slug}-{int(time.time())}"
        tree = root / "tree"
        tree.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(src) as zf:
            # ── ORDER MATTERS, AND IT WAS BACKWARDS ────────────────────
            # `zf.testzip()` fully DECOMPRESSES every member to check its
            # CRC. It used to run here, BEFORE _safe_members -- which is
            # the function holding the zip-bomb caps. So the archive that
            # the size cap exists to refuse was expanded in full, all of
            # it, before anything was allowed to say no. The caps were
            # sound; they were simply consulted second.
            #
            # A 700 KB archive declaring 1.2 GB of content is refused by
            # _safe_members in microseconds off the central directory,
            # and cost seconds of CPU to testzip first. Scale the
            # declared size up and the pre-check never returns.
            #
            # So: filter first, then verify CRCs -- and verify only the
            # members that survived the filter, since a rejected entry is
            # never going to be written and its integrity is irrelevant.
            members, rejected = _safe_members(zf, str(tree))
            if not members:
                return {"ok": False,
                        "error": "archive contained no extractable files",
                        "rejected": rejected[:40]}
            # Same guarantee testzip gave -- corruption is found before a
            # single byte is written -- at the cost of the accepted set
            # only, and streamed rather than materialised.
            for info in members:
                try:
                    with zf.open(info) as fh:
                        while fh.read(1 << 20):
                            pass
                except Exception as exc:
                    return {"ok": False,
                            "error": (f"archive is corrupt (bad entry: "
                                      f"{info.filename}: "
                                      f"{type(exc).__name__})")}
            for info in members:
                zf.extract(info, str(tree))

        # Many repo zips wrap everything in a single top directory.  Hoist
        # it so paths the operator types match what he sees on GitHub --
        # "basilisk_core.py", not "PriestsBasilisk-main/basilisk_core.py".
        entries = [p for p in tree.iterdir() if p.name != "__MACOSX"]
        if len(entries) == 1 and entries[0].is_dir():
            inner = entries[0]
            for item in list(inner.iterdir()):
                shutil.move(str(item), str(tree / item.name))
            inner.rmdir()

        count = 0
        total = 0
        secrets: List[str] = []
        for dirpath, dirnames, filenames in os.walk(tree):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                fp = Path(dirpath) / fn
                rel = str(fp.relative_to(tree))
                count += 1
                try:
                    total += fp.stat().st_size
                except OSError:
                    pass
                if _is_secret(rel):
                    secrets.append(rel)

        _orig = root / "_originals"
        _orig.mkdir(exist_ok=True)

        _STATE.name = slug
        _STATE.root = str(tree)
        _STATE.source_zip = src
        _STATE.imported_at = time.time()
        _STATE.file_count = count
        _STATE.total_bytes = total
        _STATE.modified = []
        _STATE.created = []
        _STATE.deleted = []
        _STATE.notes = []
        _STATE.edits_since_verify = 0
        _STATE.last_verdict = ""
        _STATE.verify_count = 0
        _BASELINE.clear()   # same reason as in close(): a baseline belongs
                            # to exactly one repo

        out: Dict[str, Any] = {
            "ok": True, "workspace": slug, "root": str(tree),
            "files": count, "bytes": total,
        }
        if rejected:
            out["rejected"] = rejected[:40]
            out["rejected_count"] = len(rejected)
            out["note"] = ("Some entries were refused for safety — see "
                           "`rejected`. Nothing was written for those.")
        if secrets:
            # Surfaced, not read.  The operator decides.
            out["possible_secrets"] = secrets[:20]
            out["secrets_warning"] = (
                f"{len(secrets)} file(s) look like credentials. They are "
                f"excluded from search results and from the export unless "
                f"you pass include_secrets=True.")
        _log(f"imported {slug}: {count} files, {total / 1e6:.1f} MB")
        return out
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def import_dir(path: str, name: str = "") -> Dict[str, Any]:
    """Open a repo that is already a DIRECTORY on disk, not a zip.

    Why this exists: workspace_import took a .zip and nothing else, so
    "work on my repo" meant "go zip your repo first". A checkout is the
    normal shape a repo comes in, and the whole point of the workspace is to
    be the thing that works a whole repo.

    A COPY is made, exactly as for a zip, and every later path is confined to
    that copy. That is deliberate and not laziness: the operator's own tree is
    never edited in place, revert always has something to revert TO, and
    workspace_export stays the one moment work leaves the sandbox. Symlinks
    are not followed (a link out of the tree is how a confined workspace stops
    being confined); build and vcs noise is skipped; the same file-count and
    total-size caps apply.
    """
    try:
        # ── AN EMPTY PATH IS NOT "HERE" ──
        # os.path.realpath("") is the CURRENT WORKING DIRECTORY, so a call
        # with a missing, empty or wrong-typed path silently imported whatever
        # directory the app happened to be running in — for an installed copy,
        # its own source tree. A model that put the repo in the wrong argument
        # key got a confident "imported 340 files" for a repo it never named.
        # Refuse, and say what was wanted.
        if not isinstance(path, str) or not path.strip():
            return {"ok": False,
                    "error": "no directory given — pass the path to the repo"}
        src = os.path.realpath(os.path.expanduser(path.strip()))
        if not src or not os.path.isdir(src):
            return {"ok": False, "error": f"not a directory: {path}"}

        slug = re.sub(r"[^A-Za-z0-9._-]+", "-",
                      name or os.path.basename(src.rstrip("/"))).strip("-") \
            or "repo"
        root = _base() / f"{slug}-{int(time.time())}"
        tree = root / "tree"
        tree.mkdir(parents=True, exist_ok=True)

        count = 0
        total = 0
        secrets: List[str] = []
        skipped: List[str] = []
        for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
            dirnames[:] = [d for d in dirnames
                           if d not in SKIP_DIRS
                           and not os.path.islink(os.path.join(dirpath, d))]
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                rel = os.path.relpath(fp, src)
                if os.path.islink(fp):
                    skipped.append(f"{rel} (symlink)")
                    continue
                try:
                    st = os.lstat(fp)
                except OSError as e:
                    skipped.append(f"{rel} ({type(e).__name__})")
                    continue
                if not stat.S_ISREG(st.st_mode):
                    skipped.append(f"{rel} (not a regular file)")
                    continue
                if count >= MAX_FILES:
                    skipped.append(f"{rel} (file-count cap {MAX_FILES})")
                    break
                if total + st.st_size > MAX_TOTAL_UNPACKED:
                    skipped.append(f"{rel} (total size cap)")
                    break
                dest = tree / rel
                try:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(fp, str(dest))
                except Exception as e:
                    skipped.append(f"{rel} ({type(e).__name__})")
                    continue
                count += 1
                total += st.st_size
                if _is_secret(rel):
                    secrets.append(rel)

        if count == 0:
            return {"ok": False,
                    "error": f"no readable files under {path}",
                    "skipped": skipped[:40]}

        (root / "_originals").mkdir(exist_ok=True)

        _STATE.name = slug
        _STATE.root = str(tree)
        # The directory it came from, in the field the zip path uses — status
        # and export both read this, and a workspace with no source recorded
        # reports as if it came from nowhere.
        _STATE.source_zip = src
        _STATE.imported_at = time.time()
        _STATE.file_count = count
        _STATE.total_bytes = total
        _STATE.modified = []
        _STATE.created = []
        _STATE.deleted = []
        _STATE.notes = []
        _STATE.edits_since_verify = 0
        _STATE.last_verdict = ""
        _STATE.verify_count = 0
        _BASELINE.clear()

        out: Dict[str, Any] = {
            "ok": True, "workspace": slug, "root": str(tree),
            "files": count, "bytes": total, "source": src,
            "note": ("Working on a COPY — your own directory is untouched. "
                     "workspace_export writes the result back out as a zip."),
        }
        if skipped:
            out["skipped"] = skipped[:40]
            out["skipped_count"] = len(skipped)
        if secrets:
            out["possible_secrets"] = secrets[:20]
            out["secrets_warning"] = (
                f"{len(secrets)} file(s) look like credentials. They are "
                f"excluded from search results and from the export unless "
                f"you pass include_secrets=True.")
        _log(f"imported dir {slug}: {count} files, {total / 1e6:.1f} MB")
        return out
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# ═════════════════════════════════════════════════════════════════════
# ORIENT
# ═════════════════════════════════════════════════════════════════════

def status() -> Dict[str, Any]:
    if not _STATE.root:
        return {"ok": True, "open": False,
                "hint": "No workspace open. Call workspace_import with the "
                        "repo's path (a directory or a .zip)."}
    d = asdict(_STATE)
    d.update({"ok": True, "open": True,
              "dirty": bool(_STATE.modified or _STATE.created
                            or _STATE.deleted),
              "export_blocked": _export_gate() is not None})
    return d


def tree(max_entries: int = 400, path: str = "") -> Dict[str, Any]:
    """Directory listing, noise filtered, for getting oriented fast."""
    try:
        root = _require()
        start = _confine(root, path or ".")
        rows: List[str] = []
        truncated = False
        for dirpath, dirnames, filenames in os.walk(start):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            rel_dir = os.path.relpath(dirpath, root)
            if rel_dir == ".":
                rel_dir = ""
            for fn in sorted(filenames):
                rel = os.path.join(rel_dir, fn) if rel_dir else fn
                if _skip_path(rel):
                    continue
                rows.append(rel)
                if len(rows) >= max_entries:
                    truncated = True
                    break
            if truncated:
                break
        return {"ok": True, "root": root, "count": len(rows),
                "truncated": truncated, "files": rows}
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def overview() -> Dict[str, Any]:
    """What KIND of repo is this: languages, entry points, test layout,
    dependency manifests.  One call to replace ten exploratory reads."""
    try:
        root = _require()
        langs: Dict[str, int] = {}
        loc: Dict[str, int] = {}
        manifests: List[str] = []
        test_files: List[str] = []
        entry: List[str] = []
        biggest: List[Tuple[int, str]] = []

        MANIFEST_NAMES = {
            "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
            "Pipfile", "package.json", "go.mod", "Cargo.toml", "pom.xml",
            "build.gradle", "Gemfile", "composer.json", "Makefile",
            "Dockerfile", "docker-compose.yml", "install.sh",
        }
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                rel = os.path.relpath(os.path.join(dirpath, fn), root)
                if _skip_path(rel):
                    continue
                suf = Path(fn).suffix.lower()
                lang = LANG_BY_SUFFIX.get(suf)
                if lang:
                    langs[lang] = langs.get(lang, 0) + 1
                if fn in MANIFEST_NAMES:
                    manifests.append(rel)
                low = rel.lower()
                if ("test" in low or "spec" in low) and lang:
                    test_files.append(rel)
                if fn in ("main.py", "__main__.py", "app.py", "index.js",
                          "main.go", "main.rs", "manage.py"):
                    entry.append(rel)
                try:
                    sz = os.path.getsize(os.path.join(dirpath, fn))
                except OSError:
                    continue
                if lang:
                    try:
                        with open(os.path.join(dirpath, fn), "r",
                                  encoding="utf-8", errors="replace") as f:
                            n = sum(1 for _ in f)
                        loc[lang] = loc.get(lang, 0) + n
                    except OSError:
                        pass
                biggest.append((sz, rel))

        biggest.sort(reverse=True)
        return {
            "ok": True,
            "workspace": _STATE.name,
            "languages": dict(sorted(langs.items(),
                                     key=lambda kv: -kv[1])),
            "lines_of_code": dict(sorted(loc.items(), key=lambda kv: -kv[1])),
            "manifests": sorted(manifests),
            "entry_points": sorted(entry),
            "test_files": sorted(test_files)[:40],
            "test_count": len(test_files),
            "largest_files": [{"path": p, "bytes": s}
                              for s, p in biggest[:15]],
        }
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def search(pattern: str, glob: str = "", regex: bool = False,
           max_results: int = 120, context: int = 0) -> Dict[str, Any]:
    """Repo-wide grep.  This is the tool that makes whole-repo work possible
    -- without it the model guesses filenames and reads the wrong ones."""
    try:
        root = _require()
        if not pattern:
            return {"ok": False, "error": "empty pattern"}
        if regex:
            try:
                rx = re.compile(pattern)
            except re.error as e:
                return {"ok": False, "error": f"bad regex: {e}"}
        else:
            rx = re.compile(re.escape(pattern), re.IGNORECASE)

        hits: List[Dict[str, Any]] = []
        scanned = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                rel = os.path.relpath(os.path.join(dirpath, fn), root)
                if _skip_path(rel) or _is_secret(rel):
                    continue
                if glob and not fnmatch.fnmatch(rel, glob) \
                        and not fnmatch.fnmatch(fn, glob):
                    continue
                fp = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(fp) > 4_000_000:
                        continue
                    with open(fp, "r", encoding="utf-8", errors="replace") as f:
                        lines = f.read().splitlines()
                except OSError:
                    continue
                scanned += 1
                for i, line in enumerate(lines, 1):
                    if rx.search(line):
                        row: Dict[str, Any] = {
                            "path": rel, "line": i,
                            "text": line[:300].rstrip()}
                        if context:
                            lo = max(0, i - 1 - context)
                            hi = min(len(lines), i + context)
                            row["context"] = [
                                f"{lo + k + 1}: {lines[lo + k][:200]}"
                                for k in range(hi - lo)]
                        hits.append(row)
                        if len(hits) >= max_results:
                            return {"ok": True, "pattern": pattern,
                                    "files_scanned": scanned,
                                    "count": len(hits), "truncated": True,
                                    "hits": hits}
        return {"ok": True, "pattern": pattern, "files_scanned": scanned,
                "count": len(hits), "truncated": False, "hits": hits}
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def _as_line(v: Any) -> int:
    """Coerce a model-supplied line number to a sane int.

    start/end arrive as whatever the model typed — "5000", 5000.0, None,
    True, "abc". A bool is rejected explicitly (True would read as line 1),
    and anything unusable becomes 0, which the caller reads as "unset".
    """
    if isinstance(v, bool) or v is None:
        return 0
    try:
        n = int(str(v).strip())
    except Exception:
        return 0
    if n < 0 or n > 100_000_000:
        return 0
    return n


def read(path: str, start: int = 1, end: int = 0,
         max_bytes: int = 200_000) -> Dict[str, Any]:
    """Read a workspace file, optionally a line range."""
    try:
        # Coerce the line numbers BEFORE anything compares them. `start` and
        # `end` come straight from the model, and `start > 1` on a None raises
        # a TypeError that surfaces as "the read tool is broken".
        # Remember whether a range was ASKED FOR, separately from whether it
        # parsed. "start=-4" is unusable, but silently serving the whole file
        # instead is a mode switch the caller never sees — and a whole-file
        # read of a big file is the exact input that gets written back with
        # its tail missing. Refuse instead.
        _range_asked = not (start in (None, 0, 1, "", "1") and
                            end in (None, 0, "", "0"))
        start = _as_line(start)
        end = _as_line(end)
        if _range_asked and start <= 0 and end <= 0:
            return {"ok": False,
                    "error": ("unusable line range — start/end must be "
                              "positive line numbers (1-based); omit both to "
                              "read the whole file")}
        root = _require()
        fp = _confine(root, path)
        rel = os.path.relpath(fp, root)
        if _is_secret(rel):
            return {"ok": False, "path": rel,
                    "error": "refused: this file looks like a credential "
                             "store. Read it yourself if you need it — it is "
                             "not going into a cloud model's context."}
        if not os.path.isfile(fp):
            return {"ok": False, "error": f"no such file in workspace: {path}"}
        size = os.path.getsize(fp)
        with open(fp, "rb") as f:
            raw = f.read(max_bytes)
        if b"\x00" in raw:
            return {"ok": True, "path": rel, "size": size, "kind": "binary",
                    "content": raw[:512].hex()}
        # ── A RANGED READ MUST NOT BE CLIPPED TO THE FIRST max_bytes ──
        # This branch used to slice `lines`, which came from `raw` — the first
        # 200 KB of the file. So on any file bigger than that, asking for
        # lines 5000-5100 returned NOTHING, and `total_lines` was counted from
        # the truncated text, so the file also looked shorter than it is.
        #
        # That is not a corner case: it is the exact move the truncated-read
        # note above TELLS the model to make ("read the remainder with
        # start/end"). The advice was sound and the tool could not honour it,
        # which is why paging through a large source file to fix it did not
        # work. A range is served by walking the file line by line instead —
        # the whole file, not a prefix of it — with the byte budget applied to
        # the SELECTED lines rather than to the file's opening.
        if start > 1 or end:
            lo = max(0, start - 1)
            hi = end if end > 0 else 0
            sel: List[str] = []
            total = 0
            budget = max_bytes
            clipped = False
            with open(fp, "rb") as f:
                for i, bline in enumerate(f):
                    total += 1
                    if i < lo or (hi and i >= hi):
                        continue
                    if clipped:
                        continue
                    budget -= len(bline)
                    if budget < 0:
                        clipped = True
                        continue
                    sel.append(bline.decode("utf-8", "replace")
                               .rstrip("\n").rstrip("\r"))
            body = "\n".join(f"{lo + k + 1}\t{s}" for k, s in enumerate(sel))
            out = {"ok": True, "path": rel, "size": size, "kind": "text",
                   "total_lines": total,
                   "shown": f"{lo + 1}-{lo + len(sel)}" if sel else "none",
                   "truncated": clipped,
                   "content": body}
            if clipped:
                out["note"] = (
                    f"INCOMPLETE RANGE — the requested range was cut at "
                    f"{max_bytes} bytes; you have lines {lo + 1}-"
                    f"{lo + len(sel)} of {total}. Ask for a smaller range to "
                    f"see the rest. Do NOT write this back as the whole file.")
                out["content"] = body + (
                    f"\n\n[INCOMPLETE: range cut at line {lo + len(sel)} "
                    f"of {total}]")
            elif not sel:
                out["note"] = (f"no lines in that range — the file has "
                               f"{total} lines")
            return out
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        total = len(lines)
        # ── A TRUNCATED READ MUST SAY SO INSIDE THE CONTENT ──────────
        # A big file comes back cut at max_bytes with `truncated: true` in a
        # sibling field — and nothing in the text itself. A model that reads
        # a 4,000-line file and is then asked to fix it writes back what it
        # read, silently deleting everything past the cut. That is the
        # "scrambled code" a repo repair produces, and it looks like the model
        # dropped the tail rather than never having seen it.
        #
        # Same remedy as headroom's [INCOMPLETE] marker, for the same reason:
        # the fact has to travel WITH the payload, because a flag beside it is
        # a flag the model can skip.
        #
        # `total_lines` was a lie too — counted from the truncated text, so a
        # 5,200-line file reported 4,099 and the model believed it had all of
        # it. Counted from the real file now.
        if size > max_bytes:
            _real_total = total
            try:
                with open(fp, "rb") as _f:
                    _real_total = sum(1 for _ in _f)
            except Exception:
                pass
            return {
                "ok": True, "path": rel, "size": size, "kind": "text",
                "total_lines": _real_total, "shown_lines": total,
                "truncated": True,
                "note": (f"INCOMPLETE READ — you have the first {total} of "
                         f"{_real_total} lines ({len(raw)} of {size} bytes). "
                         f"Do NOT write this back as the whole file; that "
                         f"would delete the rest. Read the remainder with "
                         f"start/end, or edit with workspace_replace."),
                "content": (text + f"\n\n[INCOMPLETE: file continues past "
                                   f"line {total} of {_real_total} — "
                                   f"{size - len(raw)} bytes not shown]"),
            }
        return {"ok": True, "path": rel, "size": size, "kind": "text",
                "total_lines": total, "truncated": False,
                "content": text}
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# ═════════════════════════════════════════════════════════════════════
# EDIT
# ═════════════════════════════════════════════════════════════════════

# A file that did not exist at import gets an explicit marker beside the
# stash, NOT an empty stash file.
#
# "Did not exist at import" used to be encoded TWICE — as zero bytes in the
# stash, and as membership in _STATE.created — and revert() had to consult
# both to decide whether to RESTORE the file or REMOVE it.  Two encodings of
# one fact is the shape every other bug in this codebase has had, and it made
# the state incoherent on the way through: _mark() could not drop a file from
# `created` when it was deleted (leaving it listed as created AND deleted at
# the same time), because dropping it would have flipped revert from "remove
# it" to "restore it as an EMPTY file".  The two encodings had to be kept
# deliberately out of sync for the result to come out right.
#
# One marker file, one meaning, one place to read it.  It also un-breaks the
# genuinely-empty imported file, which is byte-identical to the old
# "didn't exist" marker and could only be told apart by that second encoding.
_ABSENT_SUFFIX = ".basilisk-absent-at-import"


def _absent_marker(od: Path, rel: str) -> Path:
    return od / (rel + _ABSENT_SUFFIX)


def _was_absent_at_import(od: Path, rel: str) -> bool:
    return _absent_marker(od, rel).exists()


def _stash_original(root: str, fp: str, rel: str) -> None:
    """Keep the pre-edit bytes ONCE per file, the first time it changes.

    Once per file, not once per edit: after three edits the "original" must
    still be what arrived in the zip, or revert walks back one step and
    calls it done.
    """
    od = _orig_dir()
    dest = od / rel
    marker = _absent_marker(od, rel)
    if dest.exists() or marker.exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    if os.path.exists(fp):
        shutil.copy2(fp, dest)
    else:
        marker.write_bytes(b"")        # this file did not exist at import


def _mark(rel: str, kind: str) -> None:
    # Every mutation invalidates the last verdict.  Counting them is what
    # makes "one change at a time" enforceable instead of advisory: the
    # persona has always ASKED for it, and nothing stopped the model
    # batching six edits and verifying once, which loses exactly the
    # attribution the loop exists to provide -- you learn something broke,
    # not which change broke it.
    _STATE.edits_since_verify += 1
    if kind == "created":
        if rel not in _STATE.created:
            _STATE.created.append(rel)
    elif kind == "deleted":
        if rel not in _STATE.deleted:
            _STATE.deleted.append(rel)
        # A deleted file is no longer a modified one OR a created one.  Only
        # `modified` was cleared, so a file created and then deleted in the
        # same session was reported as created AND deleted simultaneously —
        # incoherent to the operator and to the model reading status().  It
        # could not be fixed while `created` doubled as revert's "this had no
        # original" flag; now that the marker carries that, it can.
        for lst in (_STATE.modified, _STATE.created):
            if rel in lst:
                lst.remove(rel)
    else:
        if rel not in _STATE.modified and rel not in _STATE.created:
            _STATE.modified.append(rel)


def _parses(src: str) -> bool:
    try:
        ast.parse(src)
        return True
    except SyntaxError:
        return False
    except Exception:
        # A null byte or a decoding oddity is not a syntax verdict; do not let
        # it masquerade as one and block an edit.
        return True


def _syntax_check(rel: str, content: str,
                  before: Optional[str] = None) -> Optional[str]:
    """Refuse a .py write that BREAKS the file. Allow one that leaves an
    already-broken file broken.

    Mirrors the core's own self-edit guard, and the reasoning still holds: a
    syntax error introduced at step 3 of a 30-step refactor gets blamed on
    step 27, so catching it at write time is the difference between a one-line
    fix and an archaeology session.

    ── BUT IT DEADLOCKED THE ONE JOB IT IS FOR ──
    The check looked only at the RESULT, so any edit to a file that did not
    already parse was refused — including an edit that had nothing to do with
    the breakage:

        repo file broken at line 1
        replace "return 2" -> "return 22" somewhere at line 5
        => "refused: Python syntax error at line 1. Nothing was written."

    The model did not cause that error and was not trying to fix it, but the
    message reads as a complaint about ITS edit, so it retries with different
    escaping and is refused identically. Reported as "the tool doesn't let it".
    And it is a genuine deadlock: a broken file could only ever be edited by an
    edit that made the whole file valid in ONE shot, which is exactly what
    repairing a repo with several faults cannot do.

    The guard that was actually wanted is a COMPARISON. Breaking working code
    is refused, as before. Leaving a pre-existing break in place is allowed and
    REPORTED, so the model knows the file still does not parse and keeps
    going instead of fighting the tool.
    """
    if not rel.endswith(".py"):
        return None
    if _parses(content):
        return None
    try:
        ast.parse(content)
    except SyntaxError as e:
        _where, _msg = e.lineno, e.msg
    except Exception:
        return None
    # `before is None` means the caller could not supply the previous text
    # (a create). Nothing existed to be broken, so the strict rule stands.
    if before is not None and not _parses(before):
        return None
    return (f"refused: Python syntax error at line {_where} "
            f"({_msg}). Nothing was written.")


def _still_broken_note(rel: str, content: str) -> str:
    """The honest half of the rule above: say the file still does not parse."""
    if rel.endswith(".py") and not _parses(content):
        return ("written, but this file STILL does not parse as Python — it "
                "was already broken before this edit and remains so. Keep "
                "fixing it; run the tests before calling it done.")
    return ""


def write(path: str, content: str, create: bool = False) -> Dict[str, Any]:
    """Write a whole file inside the workspace."""
    try:
        root = _require()
        fp = _confine(root, path)
        rel = os.path.relpath(fp, root)
        if len(content.encode("utf-8")) > MAX_EDIT_BYTES:
            return {"ok": False, "error": "content over the 8 MB write cap"}
        existed = os.path.isfile(fp)
        if not existed and not create:
            return {"ok": False, "path": rel,
                    "error": "file does not exist; pass create=True to make "
                             "a new one (guards against a typo'd path "
                             "silently creating a stray file)"}
        # The PREVIOUS text is read first because the syntax guard is now a
        # comparison — it refuses an edit that breaks working code, not one
        # that leaves an already-broken file broken. See _syntax_check.
        _prev = None
        if existed:
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    _prev = f.read()
            except Exception:
                _prev = None
        err = _syntax_check(rel, content, _prev)
        if err:
            return {"ok": False, "path": rel, "error": err,
                    "syntax_error": True}
        with _LOCK:
            old = _prev or ""
            if existed and _prev is None:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    old = f.read()
            _stash_original(root, fp, rel)
            os.makedirs(os.path.dirname(fp), exist_ok=True)
            tmp = f"{fp}.{threading.get_ident():x}.bz-tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(tmp, fp)
            _mark(rel, "created" if not existed else "modified")
        diff = list(difflib.unified_diff(
            old.splitlines(), content.splitlines(),
            fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm="", n=2))
        _res = {"ok": True, "path": rel, "created": not existed,
                "bytes": len(content.encode("utf-8")),
                "diff": "\n".join(diff[:200]) or "(new file)"}
        _note = _still_broken_note(rel, content)
        if _note:
            _res["note"] = _note
            _res["parses"] = False
        return _res
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def replace(path: str, old: str, new: str, count: int = 1) -> Dict[str, Any]:
    """Exact-substring replacement — the surgical edit.

    Why this exists alongside write(): whole-file writes make the model
    re-emit an entire file to change three lines, which burns output tokens
    (the thing v7.9.4 established is the actual latency cost) and risks it
    quietly dropping a function it did not think was important. A targeted
    replace sends only what changes.

    UNIQUENESS IS ENFORCED. If `old` appears more times than `count`, this
    refuses rather than picking one. Guessing which match was meant is how
    an agent edits the wrong call site in a file with four similar blocks.
    """
    try:
        root = _require()
        fp = _confine(root, path)
        rel = os.path.relpath(fp, root)
        if not os.path.isfile(fp):
            return {"ok": False, "error": f"no such file: {path}"}
        if not old:
            return {"ok": False, "error": "empty search string"}
        # The whole read-modify-write is ONE critical section, and it is taken
        # with `with`, not acquire()/release().  The previous version acquired
        # the lock and only THEN entered the try — so an OSError from the open()
        # below (file deleted between the isfile check and here, permission
        # change, a decode fault) escaped with the lock still held, and every
        # later workspace edit from any thread blocked on it forever.  Exactly
        # the shape v7.11.0 established as the rule: never a bare acquire in an
        # error-prone path.
        with _LOCK:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                body = f.read()
            found = body.count(old)
            if found == 0:
                return {"ok": False, "path": rel,
                        "error": "search string not found — read the file "
                                 "and match it exactly, including whitespace"}
            if found > count:
                return {"ok": False, "path": rel, "occurrences": found,
                        "error": f"search string appears {found} times but "
                                 f"count={count}. Widen it with surrounding "
                                 f"lines until it is unique, or raise count "
                                 f"deliberately."}
            updated = body.replace(old, new, count)
            # `body` is the file as it was, so the guard can tell "this edit
            # broke it" from "it was already broken". Refusing the second is
            # what deadlocked repo repair.
            err = _syntax_check(rel, updated, body)
            if err:
                return {"ok": False, "path": rel, "error": err,
                        "syntax_error": True}
            _stash_original(root, fp, rel)
            tmp = f"{fp}.{threading.get_ident():x}.bz-tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(updated)
            os.replace(tmp, fp)
            _mark(rel, "modified")
        diff = list(difflib.unified_diff(
            body.splitlines(), updated.splitlines(),
            fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm="", n=2))
        _res = {"ok": True, "path": rel, "replaced": found,
                "diff": "\n".join(diff[:120])}
        _note = _still_broken_note(rel, updated)
        if _note:
            _res["note"] = _note
            _res["parses"] = False
        return _res
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# ══════════════════════════════════════════════════════════════════════
#  THE TOOLS A REAL CODING AGENT NEEDS
# ══════════════════════════════════════════════════════════════════════
# write() and replace() are enough to edit a file and not enough to work a
# repo. The gap showed up as the operator's complaint that long code "keeps
# failing", and it is three separate ceilings wearing one symptom:
#
#   1. ONE EDIT PER ROUND-TRIP. A rename touching nine call sites is nine
#      model turns, and every one of them is a chance to lose the thread,
#      hit the step budget, or half-apply a change and leave the file in a
#      state that does not parse.
#   2. A FILE MUST FIT IN ONE REPLY. write() takes the whole file, so the
#      largest file the agent can create is bounded by max_tokens. Past
#      that the reply is cut off mid-function and the write either fails or
#      lands truncated — which is the bug the v1.1.4.0 truncation guard
#      catches, correctly, while leaving the agent with no way to write the
#      file at all. A guard that blocks the only route is half a fix.
#   3. NO WAY TO FIND FILES BY SHAPE. search() greps CONTENT; there was no
#      "every test file", "every yaml under deploy/".
#
# So: edits() applies many edits atomically, append() builds a long file in
# pieces, insert() puts a block at a line, glob() finds by name, and
# read_many() reads several files in one round-trip.
#
# ATOMICITY IS THE POINT OF edits(). Applying four of six edits and
# reporting a failure leaves the file in a state nobody designed and the
# model holding a stale picture of it. Everything is validated against an
# in-memory copy first, and the file is touched only if all of it applies.


def edits(path: str, items: Any) -> Dict[str, Any]:
    """Apply SEVERAL exact-substring edits to one file, all or nothing.

    `items` is a list of {"old": ..., "new": ..., "count": 1}. Every edit is
    checked and applied to an in-memory copy first; the file is written only
    if all of them land AND the result still parses. A failure names the
    edit that failed by index and changes nothing.

    Edits apply IN ORDER, each to the result of the last, so an edit may
    legitimately target text an earlier edit produced.
    """
    try:
        root = _require()
        fp = _confine(root, path)
        rel = os.path.relpath(fp, root)
        if not os.path.isfile(fp):
            return {"ok": False, "error": f"no such file: {path}"}
        try:
            if isinstance(items, dict):
                items = [items]
            items = list(items or [])
        except Exception:
            items = []
        if not items:
            return {"ok": False, "error": (
                'no edits given. Pass a list: {"path": "src/a.py", "edits": '
                '[{"old": "<exact text>", "new": "<replacement>"}, ...]}')}
        if len(items) > 100:
            return {"ok": False, "error": (
                f"{len(items)} edits in one call is too many (cap 100). "
                f"Split it, and verify between batches.")}
        norm = []
        for i, it in enumerate(items):
            if not isinstance(it, dict):
                return {"ok": False, "error": (
                    f"edit {i + 1} is not an object. Each edit is "
                    f'{{"old": "...", "new": "..."}}.')}
            old = it.get("old", it.get("old_str", it.get("find",
                         it.get("search", ""))))
            new = it.get("new", it.get("new_str", it.get("replace",
                         it.get("replacement", ""))))
            try:
                cnt = int(it.get("count", it.get("n", 1)) or 1)
            except Exception:
                cnt = 1
            if not isinstance(old, str) or not old:
                return {"ok": False, "error": (
                    f"edit {i + 1} has no `old` text to find.")}
            norm.append((old, new if isinstance(new, str) else str(new or ""),
                         max(1, cnt)))

        with _LOCK:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                body = f.read()
            work = body
            applied = []
            for i, (old, new, cnt) in enumerate(norm, 1):
                found = work.count(old)
                if found == 0:
                    return {"ok": False, "path": rel, "failed_edit": i,
                            "applied": 0,
                            "error": (
                                f"edit {i} of {len(norm)}: search string not "
                                f"found. NOTHING was written — the file is "
                                f"unchanged. Read the file and match the text "
                                f"exactly, including indentation. (If an "
                                f"earlier edit in this same call was meant to "
                                f"create this text, check its replacement.)")}
                if found > cnt:
                    return {"ok": False, "path": rel, "failed_edit": i,
                            "occurrences": found, "applied": 0,
                            "error": (
                                f"edit {i} of {len(norm)}: that text appears "
                                f"{found} times but count={cnt}. NOTHING was "
                                f"written. Widen it with surrounding lines "
                                f"until it is unique, or set count "
                                f"deliberately.")}
                work = work.replace(old, new, cnt)
                applied.append({"edit": i, "replaced": found})
            err = _syntax_check(rel, work, body)
            if err:
                return {"ok": False, "path": rel, "syntax_error": True,
                        "applied": 0,
                        "error": (f"the file would not parse after these "
                                  f"edits, so NOTHING was written: {err}")}
            _stash_original(root, fp, rel)
            tmp = f"{fp}.{threading.get_ident():x}.bz-tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(work)
            os.replace(tmp, fp)
            _mark(rel, "modified")
        diff = list(difflib.unified_diff(
            body.splitlines(), work.splitlines(),
            fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm="", n=2))
        res = {"ok": True, "path": rel, "edits_applied": len(norm),
               "details": applied,
               "lines_before": len(body.splitlines()),
               "lines_after": len(work.splitlines()),
               "diff": "\n".join(diff[:200])}
        note = _still_broken_note(rel, work)
        if note:
            res["note"] = note
            res["parses"] = False
        return res
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def append(path: str, content: str, create: bool = False) -> Dict[str, Any]:
    """Add text to the END of a file — the way to write a LONG one.

    THIS IS THE ANSWER TO "it can't write big files". A whole-file write has
    to fit in one model reply, so past a few hundred lines the reply is cut
    off at max_tokens and the file lands truncated or the write is refused.
    Neither leaves the agent anywhere to go.

    The protocol is: write the first chunk with create=true, then append
    each following chunk, then verify. Each chunk is its own round-trip and
    its own modest reply, so file size stops being bounded by reply size.

    NO SYNTAX GATE ON A CHUNK, deliberately: a half-written Python file does
    not parse and must not be refused for it, or the protocol cannot get
    past its first chunk. The check that matters still happens — the file is
    re-checked when it is next written whole or edited, and workspace_verify
    runs the real thing. `parses` is REPORTED on every append so a file left
    unparseable at the end of a chunk sequence is visible rather than
    silent.
    """
    try:
        root = _require()
        fp = _confine(root, path)
        rel = os.path.relpath(fp, root)
        content = content if isinstance(content, str) else str(content or "")
        existed = os.path.isfile(fp)
        if not existed and not create:
            return {"ok": False, "path": rel, "error": (
                "file does not exist. For the FIRST chunk of a new file pass "
                'create=true; for later chunks it already exists.')}
        with _LOCK:
            old = ""
            if existed:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    old = f.read()
            if len((old + content).encode("utf-8")) > MAX_EDIT_BYTES:
                return {"ok": False, "path": rel,
                        "error": "file would exceed the 8 MB cap"}
            _stash_original(root, fp, rel)
            os.makedirs(os.path.dirname(fp), exist_ok=True)
            # A chunk boundary that lands mid-line silently joins two lines
            # of code. If the file so far ends without a newline and the new
            # chunk does not start one, the join is almost certainly an
            # accident — but it is the model's call, so say what was done
            # rather than deciding silently.
            joined = old + content
            tmp = f"{fp}.{threading.get_ident():x}.bz-tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(joined)
            os.replace(tmp, fp)
            _mark(rel, "created" if not existed else "modified")
        res = {"ok": True, "path": rel, "created": not existed,
               "appended_lines": len(content.splitlines()),
               "total_lines": len(joined.splitlines()),
               "bytes": len(joined.encode("utf-8")),
               "parses": _parses(joined) if rel.endswith(".py") else True}
        if old and not old.endswith("\n") and not content.startswith("\n"):
            res["joined_mid_line"] = True
            res["warning"] = (
                "the previous chunk did not end in a newline, so this chunk "
                "was joined onto its last line. If that was not intended, "
                "read the file around that point and fix it.")
        if rel.endswith(".py") and not res["parses"]:
            res["note"] = (
                "the file does not parse YET — expected mid-sequence. Keep "
                "appending; it must parse once the last chunk is in, and "
                "workspace_verify will tell you if it does not.")
        return res
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def insert(path: str, content: str, after_line: int = 0,
           before_line: int = 0) -> Dict[str, Any]:
    """Insert a block at a line position, without restating the file.

    For adding an import, a method, a case to a dispatch table — the edits
    where there is no unique anchor text to replace against, only a place.
    Line numbers are 1-based and refer to the file as it is NOW, so read it
    first; after_line=0 means the very top.
    """
    try:
        root = _require()
        fp = _confine(root, path)
        rel = os.path.relpath(fp, root)
        if not os.path.isfile(fp):
            return {"ok": False, "error": f"no such file: {path}"}
        content = content if isinstance(content, str) else str(content or "")
        with _LOCK:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                body = f.read()
            lines = body.splitlines(keepends=True)
            n = len(lines)
            a, b = _as_line(after_line), _as_line(before_line)
            if b:
                idx = max(0, min(n, b - 1))
            elif a:
                idx = max(0, min(n, a))
            else:
                idx = 0
            if a and b:
                return {"ok": False, "error": (
                    "pass after_line OR before_line, not both.")}
            if (a and a > n) or (b and b > n + 1):
                return {"ok": False, "path": rel, "lines": n, "error": (
                    f"line {a or b} is past the end of the file, which has "
                    f"{n} lines. To add at the end use workspace_append.")}
            block = content if content.endswith("\n") else content + "\n"
            updated = "".join(lines[:idx]) + block + "".join(lines[idx:])
            err = _syntax_check(rel, updated, body)
            if err:
                return {"ok": False, "path": rel, "error": err,
                        "syntax_error": True}
            _stash_original(root, fp, rel)
            tmp = f"{fp}.{threading.get_ident():x}.bz-tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(updated)
            os.replace(tmp, fp)
            _mark(rel, "modified")
        diff = list(difflib.unified_diff(
            body.splitlines(), updated.splitlines(),
            fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm="", n=2))
        return {"ok": True, "path": rel, "inserted_at_line": idx + 1,
                "inserted_lines": len(block.splitlines()),
                "total_lines": len(updated.splitlines()),
                "diff": "\n".join(diff[:120])}
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def glob_files(pattern: str = "*", limit: int = 300) -> Dict[str, Any]:
    """Find files by NAME pattern — the counterpart to search()'s content grep.

    "**/test_*.py", "src/**/*.ts", "deploy/*.yaml". Results are sorted by
    modification time, newest first, because in a repo you are working on
    the recently-touched files are almost always the ones you want.
    """
    try:
        root = _require()
        pat = (pattern or "*").strip() or "*"
        if pat.startswith("/"):
            pat = pat.lstrip("/")
        base = Path(root)
        out = []
        try:
            it = base.glob(pat)
        except Exception as e:
            return {"ok": False, "error": (
                f"bad glob pattern {pat!r}: {e}. Use shell-style patterns "
                f'like "**/*.py" or "src/*.ts".')}
        for p in it:
            try:
                if not p.is_file():
                    continue
                rel = os.path.relpath(str(p), root)
                if _skip_path(rel):
                    continue
                st = p.stat()
                out.append((st.st_mtime, rel, st.st_size))
            except Exception:
                continue
        out.sort(key=lambda t: (-t[0], t[1]))
        try:
            lim = max(1, min(2000, int(limit or 300)))
        except Exception:
            lim = 300
        files = [{"path": r, "bytes": sz} for _, r, sz in out[:lim]]
        res = {"ok": True, "pattern": pat, "count": len(out),
               "files": files}
        if not files:
            res["note"] = (
                "nothing matched. `**/` is needed to recurse — \"*.py\" only "
                "matches the repo root, \"**/*.py\" matches every directory. "
                "workspace_tree shows the real layout.")
        elif len(out) > lim:
            res["truncated"] = True
            res["note"] = (f"{len(out)} matched, showing the {lim} most "
                           f"recently modified.")
        return res
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def read_many(paths: Any, max_chars: int = 6000) -> Dict[str, Any]:
    """Read SEVERAL files in one round-trip.

    Orientation in an unfamiliar repo is a handful of reads that do not
    depend on each other — the module, its test, and the caller. Doing them
    one per turn spends three model round-trips to learn one thing.
    """
    try:
        _require()
        try:
            if isinstance(paths, str):
                paths = [p for p in re.split(r"[,\n]+", paths) if p.strip()]
            paths = list(paths or [])
        except Exception:
            paths = []
        if not paths:
            return {"ok": False, "error": (
                'no paths. Pass a list: {"paths": ["src/a.py", "tests/'
                'test_a.py"]}')}
        if len(paths) > 20:
            return {"ok": False, "error": (
                f"{len(paths)} files at once is too many (cap 20).")}
        # A FLOOR, AND IT SAYS SO. A 10-character read is not a read, so a
        # tiny max_chars is raised to something useful — but raising it
        # SILENTLY means the caller's number was ignored and nothing says
        # which number actually applied. Report it when it differs.
        _asked = max_chars
        try:
            cap = max(200, min(40000, int(max_chars or 6000)))
        except Exception:
            cap = 6000
        out = []
        for p in paths:
            rec = read(str(p).strip(), 1, 0)
            if rec.get("ok"):
                # read() returns `content` and `total_lines` — checked
                # against the real function, not assumed. A reader that
                # guesses its own callee's key shape returns empty strings
                # that look exactly like empty files.
                txt = str(rec.get("content") or "")
                out.append({"path": rec.get("path", p), "ok": True,
                            "total_lines": rec.get("total_lines"),
                            "truncated": bool(rec.get("truncated")
                                              or len(txt) > cap),
                            "content": txt[:cap]})
            else:
                out.append({"path": p, "ok": False,
                            "error": rec.get("error", "unreadable")})
        good = sum(1 for r in out if r.get("ok"))
        res = {"ok": good > 0, "read": good, "requested": len(paths),
               "chars_per_file": cap, "files": out}
        try:
            if _asked and int(_asked) != cap:
                res["max_chars_note"] = (
                    f"max_chars={_asked} was clamped to {cap} (the useful "
                    f"range is 200-40000); that is the limit actually applied.")
        except Exception:
            pass
        if good < len(paths):
            res["note"] = ("some files could not be read — check the paths "
                           "with workspace_glob or workspace_tree.")
        return res
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def repo_root() -> str:
    """The open workspace's absolute root, or "" — so the host can run
    commands with the repo as cwd instead of making the model cd."""
    try:
        return _require()
    except Exception:
        return ""


def delete(path: str) -> Dict[str, Any]:
    """Delete a file inside the workspace.  Recoverable via revert()."""
    try:
        root = _require()
        fp = _confine(root, path)
        rel = os.path.relpath(fp, root)
        if not os.path.isfile(fp):
            return {"ok": False, "error": f"no such file: {path}"}
        with _LOCK:
            _stash_original(root, fp, rel)
            recoverable = not _was_absent_at_import(_orig_dir(), rel)
            os.remove(fp)
            _mark(rel, "deleted")
        # TELL THE TRUTH ABOUT THE UNDO.  This said "recoverable with
        # workspace_revert" for every file, unconditionally.  revert() undoes
        # back to the IMPORTED state, so a file CREATED in this session has no
        # state to go back to: revert removes it and the content is gone.  The
        # note promised otherwise, which is how a self-test concluded revert
        # was silently broken — it isn't, but the operator was being told his
        # data was recoverable at the exact moment it stopped being.
        #
        # A wrong undo promise is the same defect as a wrong undo command: it
        # reads as "this is safe to do" when it is not.
        return {"ok": True, "path": rel, "deleted": True,
                "recoverable": recoverable,
                "note": ("recoverable with workspace_revert"
                         if recoverable else
                         "NOT recoverable: this file was created in this "
                         "session, so there is no imported version to go back "
                         "to. workspace_revert will leave it deleted. Its "
                         "content is gone — re-create it with workspace_write "
                         "if you still need it.")}
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def diff(path: str = "") -> Dict[str, Any]:
    """Unified diff of everything changed since import (or one file).

    This is what the operator reviews before exporting.  A change set he
    cannot see is a change set he cannot approve.
    """
    try:
        root = _require()
        od = _orig_dir()
        targets = ([path] if path
                   else sorted(set(_STATE.modified + _STATE.created
                                   + _STATE.deleted)))
        if not targets:
            return {"ok": True, "changed": 0, "diff": "",
                    "note": "no changes since import"}
        chunks: List[str] = []
        for rel in targets:
            fp = os.path.join(root, rel)
            orig_fp = od / rel
            before = ""
            if orig_fp.exists():
                before = orig_fp.read_text(encoding="utf-8", errors="replace")
            elif rel not in _STATE.created:
                continue
            after = ""
            if os.path.isfile(fp):
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    after = f.read()
            d = list(difflib.unified_diff(
                before.splitlines(), after.splitlines(),
                fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm="", n=3))
            if d:
                chunks.append("\n".join(d))
        return {"ok": True, "changed": len(targets),
                "modified": _STATE.modified, "created": _STATE.created,
                "deleted": _STATE.deleted,
                "diff": "\n\n".join(chunks)[:120_000]}
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def revert(path: str = "") -> Dict[str, Any]:
    """Undo edits — one file, or everything, back to the imported state."""
    try:
        root = _require()
        od = _orig_dir()
        targets = ([path] if path
                   else sorted(set(_STATE.modified + _STATE.created
                                   + _STATE.deleted)))
        done: List[str] = []
        restored: List[str] = []
        removed: List[str] = []
        # `with`, not acquire/release: an exception between a bare acquire
        # and its release leaves the lock held forever and every later edit
        # deadlocks -- a strictly worse failure than the race being fixed.
        with _LOCK:
            for rel in targets:
                fp = _confine(root, rel)
                orig_fp = od / rel
                # ONE question, asked once: did this file exist at import?
                absent = _was_absent_at_import(od, rel)
                # Legacy stashes (pre-marker) encoded that as zero bytes plus
                # membership in `created`.  Honour them so a workspace opened
                # across the upgrade still reverts correctly.
                if not absent and orig_fp.exists() and rel in _STATE.created \
                        and orig_fp.stat().st_size == 0:
                    absent = True
                if absent:
                    if os.path.isfile(fp):
                        os.remove(fp)
                    removed.append(rel)
                    done.append(rel)
                elif orig_fp.exists():
                    os.makedirs(os.path.dirname(fp), exist_ok=True)
                    shutil.copy2(orig_fp, fp)
                    restored.append(rel)
                    done.append(rel)
            for rel in done:
                for lst in (_STATE.modified, _STATE.created, _STATE.deleted):
                    if rel in lst:
                        lst.remove(rel)
                for op in (od / rel, _absent_marker(od, rel)):
                    if op.exists():
                        op.unlink()
        # `reverted` is the union, kept for callers that already read it.
        # `restored` vs `removed` is the distinction the operator actually
        # needs: "reverted" alone reads as "your file is back", which is a
        # lie for a file that never existed at import.
        return {"ok": True, "reverted": done, "count": len(done),
                "restored": restored, "removed": removed}
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# ═════════════════════════════════════════════════════════════════════
# EXPORT
# ═════════════════════════════════════════════════════════════════════

def _confine_export(root: str, out_path: str) -> str:
    """Resolve an export destination, or refuse it.

    `_confine` cannot be used here and that is the whole reason this bug
    existed: the DEFAULT export destination is deliberately OUTSIDE the
    workspace -- `<root>/../<name>-<stamp>.zip` -- so the operator can pick
    the zip up without digging into the sandbox. Every other path in this
    module goes through `_confine`, so `out_path` was left with no check at
    all and simply did this:

        dest = os.path.realpath(os.path.expanduser(out_path))

    which writes a zip anywhere the process can write. `export_zip(
    out_path="/etc/cron.d/x")` lands in /etc; `out_path="~/backups/2024.zip"`
    overwrites a real backup; and the `os.makedirs` that followed created
    whatever directory tree was needed to get there. The model picks this
    argument, so "it would never do that" is not a boundary.

    The rule is the smallest one that keeps the feature working: the export
    may land in the workspace, in the workspace's parent (where the default
    already goes), or under the operator's home -- and nowhere else. An
    existing file is never silently overwritten.
    """
    if not out_path:
        raise ContainmentError("empty export path")
    cand = os.path.realpath(os.path.expanduser(out_path))
    real_root = os.path.realpath(root)
    allowed = [real_root, os.path.dirname(real_root)]
    home = os.path.realpath(os.path.expanduser("~"))
    if home and home != os.sep:
        allowed.append(home)
    try:
        base = os.path.realpath(str(_base()))
        if base:
            allowed.append(base)
    except Exception:
        pass

    for a in allowed:
        if not a or a == os.sep:
            continue
        try:
            if os.path.commonpath([a, cand]) == a:
                break
        except ValueError:
            continue
    else:
        raise ContainmentError(
            "export destination %r is outside the workspace, its parent and "
            "your home directory -- refusing. Export without out_path and "
            "move the zip yourself if it really belongs there." % out_path)

    target = cand if cand.endswith(".zip") else cand + ".zip"
    if os.path.exists(target):
        raise ContainmentError(
            "export destination %r already exists -- refusing to overwrite "
            "it. Choose another name or delete it first." % target)
    return cand


def _export_gate() -> Optional[Dict[str, Any]]:
    """Reasons NOT to export.  None when it is safe to go."""
    dirty = bool(_STATE.modified or _STATE.created or _STATE.deleted)
    if not dirty:
        return None                      # nothing changed: harmless
    if _STATE.last_verdict == "regression":
        return {"ok": False, "refused": True, "reason": "regression",
                "error": ("REFUSED: the last verify said you BROKE tests "
                          "that passed at baseline. Fix them or "
                          "workspace_revert. Pass force=True only if the "
                          "operator has explicitly accepted the regression."),
                "last_verdict": _STATE.last_verdict}
    if _STATE.edits_since_verify > 0:
        return {"ok": False, "refused": True, "reason": "unverified",
                "edits_since_verify": _STATE.edits_since_verify,
                "error": (f"REFUSED: {_STATE.edits_since_verify} edit(s) have "
                          f"not been verified. Run workspace_verify. If the "
                          f"repo genuinely has no tests, say so to the "
                          f"operator and pass force=True — do not pass it "
                          f"silently."),
                "last_verdict": _STATE.last_verdict or "(never verified)"}
    return None


def export_zip(out_path: str = "", include_secrets: bool = False,
               changed_only: bool = False,
               force: bool = False) -> Dict[str, Any]:
    """Zip the working tree back up for the operator to drop over his repo.

    Excludes build noise, and excludes anything that looks like a
    credential unless explicitly asked -- a re-exported .env that gets
    committed is a worse outcome than a slightly incomplete zip, and the
    operator can always copy that one file by hand.
    """
    try:
        root = _require()
        stamp = time.strftime("%Y%m%d-%H%M%S")
        if out_path:
            try:
                dest = _confine_export(root, out_path)
            except ContainmentError as exc:
                return {"ok": False, "refused": True, "reason": "containment",
                        "error": str(exc)}
        else:
            dest = str(Path(root).parent / f"{_STATE.name}-{stamp}.zip")
        if not dest.endswith(".zip"):
            dest += ".zip"
        parent = os.path.dirname(dest)
        # Create the immediate directory if it is missing, never a tree.
        # `os.makedirs(..., exist_ok=True)` would happily conjure
        # `/opt/a/b/c` on the way to a filename, which is filesystem
        # mutation the operator never asked for.
        if parent and not os.path.isdir(parent):
            if not os.path.isdir(os.path.dirname(parent) or "/"):
                return {"ok": False, "refused": True, "reason": "containment",
                        "error": (f"refusing to create a directory tree for "
                                  f"the export: {parent!r} does not exist and "
                                  f"neither does its parent")}
            os.makedirs(parent, exist_ok=True)

        # ── EXPORT GATE ────────────────────────────────────────────────
        # Refuse to hand back a zip whose changes were never verified, or
        # whose last verified state was a REGRESSION.  This is the one
        # place a soft rule becomes a hard one, and it is deliberate: the
        # export is the moment the operator's real repo is at risk, and
        # "the model said it was fine" is not evidence. `force=True` is
        # available and reported, so an operator who knows better is never
        # locked out -- but he has to say so.
        gate = _export_gate()
        if gate and not force:
            return gate

        wanted = None
        if changed_only:
            wanted = set(_STATE.modified + _STATE.created)
            if not wanted:
                return {"ok": False,
                        "error": "changed_only=True but nothing has changed"}

        added: List[str] = []
        skipped_secrets: List[str] = []
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for fn in filenames:
                    fp = os.path.join(dirpath, fn)
                    rel = os.path.relpath(fp, root)
                    if fn.endswith(".bz-tmp"):
                        continue
                    if wanted is not None and rel not in wanted:
                        continue
                    if _is_secret(rel) and not include_secrets:
                        skipped_secrets.append(rel)
                        continue
                    if os.path.islink(fp):
                        continue          # never ship a link out either
                    zf.write(fp, rel)
                    added.append(rel)

        out: Dict[str, Any] = {
            "ok": True, "zip": dest, "files": len(added),
            "bytes": os.path.getsize(dest),
            "changed_only": changed_only,
            "modified": _STATE.modified, "created": _STATE.created,
            "deleted": _STATE.deleted,
            "last_verdict": _STATE.last_verdict or "(never verified)",
            "forced": bool(force and _export_gate()),
        }
        if out["forced"]:
            out["force_warning"] = (
                "Exported with force=True — the verification gate was "
                "bypassed. Tell the operator exactly which check was skipped.")
        if skipped_secrets:
            out["excluded_secrets"] = skipped_secrets[:20]
            out["note"] = ("Credential-looking files were left OUT. Pass "
                           "include_secrets=True if you actually want them.")
        if _STATE.deleted:
            out["deleted_note"] = (
                "Deleted files are absent from this zip. If you unzip OVER "
                "an existing checkout they will still be there — remove them "
                "by hand or unzip into a clean directory.")
        _log(f"exported {len(added)} files -> {dest}")
        return out
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def close(discard: bool = False) -> Dict[str, Any]:
    """Close the workspace.  Files stay on disk unless discard=True."""
    root = _STATE.root
    name = _STATE.name
    if not root:
        return {"ok": True, "note": "no workspace was open"}
    parent = str(Path(root).parent)
    if discard:
        shutil.rmtree(parent, ignore_errors=True)
    _STATE.__init__()      # type: ignore[misc]
    _BASELINE.clear()      # a baseline from repo A must never be compared
                           # against repo B's suite -- every name would look
                           # "fixed" and every new name "broken"
    return {"ok": True, "closed": name, "discarded": discard,
            "kept_at": None if discard else parent}


# ═════════════════════════════════════════════════════════════════════
# VERIFICATION — the part that turns "edits code" into "fixes code"
# ═════════════════════════════════════════════════════════════════════
# An agent that edits a repo and hands back a diff is guessing.  What makes
# the difference is the LOOP: establish what already fails, change one
# thing, re-run, and compare against the baseline rather than against a
# feeling.
#
# THE BASELINE IS THE WHOLE IDEA.  Without it every pre-existing failure
# looks like damage the agent just caused, and -- much worse in practice --
# a test that was ALREADY failing gets "fixed" silently and folded into the
# change set, so the operator reviews a diff containing work he never asked
# for and cannot tell apart from the work he did.  Run baseline BEFORE the
# first edit or the loop is measuring nothing.
#
# This module still executes NOTHING.  It decides WHAT to run and it
# interprets what came back; the running happens in the core wrapper, which
# routes through tool_run_command and therefore through the destructive
# floor and the scope gate unchanged.  Splitting it this way keeps the
# safety boundary in exactly one place instead of two.

_BASELINE: Dict[str, Any] = {}

# Ordered: the first detector that matches wins.  Ordering is by how
# SPECIFIC the signal is, not by popularity -- a repo with both a Makefile
# and a pytest suite usually wants `make test`, because the Makefile
# encodes setup steps that bare pytest skips.
_TEST_DETECTORS: List[Tuple[str, str, str]] = [
    ("Makefile",       "make test",                    "make"),
    ("noxfile.py",     "nox",                          "nox"),
    ("tox.ini",        "tox",                          "tox"),
    ("pytest.ini",     "python3 -m pytest -q",         "pytest"),
    ("pyproject.toml", "python3 -m pytest -q",         "pytest"),
    ("setup.cfg",      "python3 -m pytest -q",         "pytest"),
    ("package.json",   "npm test --silent",            "npm"),
    ("go.mod",         "go test ./...",                "go"),
    ("Cargo.toml",     "cargo test",                   "cargo"),
    ("Gemfile",        "bundle exec rspec",            "rspec"),
]

# Compiled once at module scope.  These run over every line of a test log,
# which for a big suite is tens of thousands of lines.
_RX_PYTEST = re.compile(
    r"(\d+) failed|(\d+) passed|(\d+) error|(\d+) skipped")
# `FAILED foo/test_x.py::test_y` (pytest). The (?!\() is not decoration:
# unittest ends its run with the summary line
#
#     FAILED (failures=2, errors=1)
#
# which this pattern happily read as a failing test called "(failures=2,".
# That fake name then went into `failed_names`, into the baseline, and out
# the other side as a test that had been "fixed" — a phantom in the one
# report the operator is meant to trust.
_RX_FAILNAME = re.compile(
    r"^(?:FAILED|ERROR)\s+(?!\()([^\s:]+(?:::[^\s]+)?)", re.M)
# unittest's own summary block. Nothing parsed it, so a repo whose tests run
# under `python -m unittest` reported counts of all zeros next to a list of
# named failures — internally contradictory, and the zeros are what a model
# quoting "0 failed" would read.
_RX_UT_RAN = re.compile(r"^Ran (\d+) tests?\b", re.M)
_RX_UT_SUMMARY = re.compile(r"^(OK|FAILED)\b(?:\s*\((.*)\))?\s*$", re.M)
_RX_UNITTEST = re.compile(r"^(?:FAIL|ERROR):\s+(\S+)", re.M)
_RX_SCRIPT_FAIL = re.compile(r"^\s*FAIL\s+(.+)$", re.M)
_RX_GO_FAIL = re.compile(r"^---\s+FAIL:\s+(\S+)", re.M)
_RX_TRACE = re.compile(r"^(\w+Error|\w+Exception):\s*(.+)$", re.M)


def detect_test_command() -> Dict[str, Any]:
    """Work out how THIS repo runs its tests.

    Returns the command plus what it was inferred from, so the operator can
    correct it rather than discovering later that Basilisk ran the wrong
    thing and declared victory.
    """
    try:
        root = _require()
        found: List[Dict[str, str]] = []
        for marker, cmd, kind in _TEST_DETECTORS:
            fp = os.path.join(root, marker)
            if not os.path.isfile(fp):
                continue
            # A Makefile without a `test:` target is not a test runner, and
            # `make test` on one fails with "No rule to make target" -- which
            # reads exactly like a broken build if you are not looking
            # closely.  Check the target actually exists.
            if marker == "Makefile":
                try:
                    with open(fp, "r", encoding="utf-8", errors="replace") as f:
                        if not re.search(r"(?m)^test\s*:", f.read()):
                            continue
                except OSError:
                    continue
            if marker == "package.json":
                try:
                    with open(fp, "r", encoding="utf-8", errors="replace") as f:
                        pkg = json.load(f)
                    if "test" not in (pkg.get("scripts") or {}):
                        continue
                except (OSError, ValueError):
                    continue
            found.append({"command": cmd, "from": marker, "kind": kind})

        # Bare test files with no manifest at all -- which is exactly this
        # repo's own shape, and a shape a manifest-only detector misses
        # entirely.
        script_tests: List[str] = []
        for d in ("tests", "test", "."):
            td = os.path.join(root, d)
            if not os.path.isdir(td):
                continue
            for fn in sorted(os.listdir(td)):
                if re.match(r"^test_.*\.py$|^.*_test\.py$", fn):
                    script_tests.append(
                        os.path.join(d, fn) if d != "." else fn)
            if script_tests:
                break

        if not found and script_tests:
            found.append({
                "command": "python3 -m pytest -q " + os.path.dirname(
                    script_tests[0] or ".") or "python3 -m pytest -q",
                "from": f"{len(script_tests)} test file(s) with no manifest",
                "kind": "pytest"})

        return {"ok": True, "candidates": found,
                "command": found[0]["command"] if found else "",
                "test_files": script_tests[:40],
                "test_file_count": len(script_tests),
                "note": ("No test runner detected — ask the operator how he "
                         "runs them rather than guessing."
                         if not found else
                         "First candidate is the best guess; confirm with the "
                         "operator if the repo is unusual.")}
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def parse_test_output(raw: str, rc: int = 0) -> Dict[str, Any]:
    """Turn a test log into counts plus the SET OF FAILING TEST NAMES.

    Names, not just counts, because counts alone cannot tell you the
    difference between "fixed one, broke another" and "nothing changed".
    Both show 3 failed.  That distinction is the entire value of the loop.
    """
    # Total by construction: this is fed subprocess output, and a runner that
    # returns bytes (or a caller that passes None) must not take the whole
    # verify step down with a TypeError from inside a regex.
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", "replace")
    elif not isinstance(raw, str):
        raw = "" if raw is None else str(raw)
    try:
        rc = int(rc)
    except Exception:
        rc = 1          # unknown exit status is NOT "it passed"
    failed_names: List[str] = []
    for rx in (_RX_FAILNAME, _RX_UNITTEST, _RX_GO_FAIL, _RX_SCRIPT_FAIL):
        for m in rx.finditer(raw):
            nm = m.group(1).strip()
            if nm and nm not in failed_names:
                failed_names.append(nm)

    counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    tail = raw[-4000:]
    for m in re.finditer(r"(\d+)\s+failed", tail):
        counts["failed"] = max(counts["failed"], int(m.group(1)))
    for m in re.finditer(r"(\d+)\s+passed", tail):
        counts["passed"] = max(counts["passed"], int(m.group(1)))
    for m in re.finditer(r"(\d+)\s+error", tail):
        counts["errors"] = max(counts["errors"], int(m.group(1)))
    for m in re.finditer(r"(\d+)\s+skipped", tail):
        counts["skipped"] = max(counts["skipped"], int(m.group(1)))

    # ── unittest, which words all of this differently ──
    #   Ran 8 tests in 0.001s
    #   FAILED (failures=2, errors=1, skipped=1)      (or a bare "OK")
    _ran = _RX_UT_RAN.findall(tail)
    _sum = _RX_UT_SUMMARY.findall(tail)
    if _ran and _sum:
        _total = int(_ran[-1])
        _verdict, _detail = _sum[-1]
        _bad = 0
        for _k, _key in (("failures", "failed"), ("errors", "errors"),
                         ("unexpected successes", "failed")):
            for m in re.finditer(re.escape(_k) + r"=(\d+)", _detail or ""):
                counts[_key] = max(counts[_key], int(m.group(1)))
        for m in re.finditer(r"skipped=(\d+)", _detail or ""):
            counts["skipped"] = max(counts["skipped"], int(m.group(1)))
        _bad = counts["failed"] + counts["errors"] + counts["skipped"]
        counts["passed"] = max(counts["passed"], max(0, _total - _bad))

    errs = [f"{m.group(1)}: {m.group(2)[:140]}"
            for m in _RX_TRACE.finditer(raw)][:12]

    # rc is the ground truth when the log is unparseable.  A runner we do
    # not have a pattern for still exits non-zero on failure, and treating
    # "I could not parse it" as "it passed" is the single worst thing this
    # function could do.
    green = (rc == 0) and not failed_names and counts["failed"] == 0
    return {"green": green, "rc": rc, "counts": counts,
            "failed_names": failed_names, "failure_count": len(failed_names),
            "exceptions": errs,
            "parsed": bool(failed_names or any(counts.values())),
            "tail": raw[-2500:]}


def record_baseline(raw: str, rc: int = 0, command: str = "") -> Dict[str, Any]:
    """Record the repo's state BEFORE any edits.  Run this first."""
    global _BASELINE
    p = parse_test_output(raw, rc)
    _BASELINE = {"command": command, "at": time.time(),
                 "green": p["green"], "counts": p["counts"],
                 "failed_names": p["failed_names"],
                 "dirty_when_taken": bool(_STATE.modified or _STATE.created
                                          or _STATE.deleted)}
    out = {"ok": True, "baseline": _BASELINE,
           "already_failing": p["failed_names"],
           "green_at_baseline": p["green"]}
    if _BASELINE["dirty_when_taken"]:
        out["warning"] = (
            "Baseline was taken AFTER files were already modified. It no "
            "longer represents the repo as imported, so 'pre-existing' "
            "below may include your own changes. Revert and re-baseline if "
            "you need a clean reading.")
    if not p["green"]:
        out["note"] = (
            f"{len(p['failed_names']) or p['counts']['failed']} test(s) were "
            f"ALREADY failing before any edit. Tell the operator — do not "
            f"silently fold fixing these into the change he asked for.")
    return out


def compare_to_baseline(raw: str, rc: int = 0) -> Dict[str, Any]:
    """Classify the current test run against the baseline.

    The four buckets are the whole point, and `broke` is the one that
    matters: a fix that repairs one test and breaks two is a regression
    wearing a fix's clothes, and counts alone will not show it.
    """
    p = parse_test_output(raw, rc)
    _STATE.verify_count += 1
    _pending = _STATE.edits_since_verify
    if not _BASELINE:
        # DO NOT CLEAR THE COUNTER HERE.
        #
        # It used to be zeroed on the line above this branch, which meant a
        # verify run with no baseline -- a run that by its own admission
        # attributes NOTHING -- reset `edits_since_verify` to 0 and left
        # `last_verdict` unset. _export_gate() checks exactly those two
        # fields, so it then found nothing to object to and opened. The
        # export gate is the one hard rule in this module, and it could be
        # unlocked by running the tests without ever having baselined them.
        #
        # An unattributable run has verified nothing, so the edits are
        # still unverified and the verdict is still absent. Say so, and let
        # the gate keep refusing until there is a real reading or the
        # operator passes force=True himself.
        _STATE.last_verdict = "no-baseline"
        return {"ok": True, "no_baseline": True, "current": p,
                "edits_still_unverified": _pending,
                "warning": ("No baseline recorded, so nothing can be "
                            "attributed. Every failure below might predate "
                            "your edits. Revert, baseline, retry.")}
    _STATE.edits_since_verify = 0
    before = set(_BASELINE.get("failed_names") or [])
    now = set(p["failed_names"])
    fixed = sorted(before - now)
    broke = sorted(now - before)
    still = sorted(now & before)

    verdict = "green" if p["green"] else (
        "regression" if broke else
        "progress" if fixed else "no-change")
    out = {
        "ok": True, "verdict": verdict, "green": p["green"],
        "fixed": fixed, "broke": broke, "still_failing": still,
        "counts_now": p["counts"],
        "counts_before": _BASELINE.get("counts"),
        "exceptions": p["exceptions"], "tail": p["tail"],
        "changed_files": sorted(set(_STATE.modified + _STATE.created)),
        "edits_covered": _pending,
    }
    _STATE.last_verdict = verdict
    if _pending > 3 and verdict != "green":
        out["attribution_warning"] = (
            f"This run covers {_pending} edits at once. If something broke, "
            f"you cannot tell which edit did it. Make ONE change per verify "
            f"— that is the whole point of the loop.")
    if broke:
        out["action"] = (
            f"YOU BROKE {len(broke)} test(s) that passed at baseline: "
            f"{', '.join(broke[:6])}. Fix these before anything else, or "
            f"workspace_revert and try a different approach. Do not export.")
    elif p["green"] and not before:
        out["action"] = "All green and nothing was failing before. Safe to diff and export."
    elif p["green"]:
        out["action"] = (
            f"All green. Note {len(before)} test(s) were already failing at "
            f"baseline and now pass — mention that to the operator so he "
            f"knows what is in the diff.")
    elif still and not fixed:
        out["action"] = (
            "Nothing moved. Re-read the actual failure output rather than "
            "editing again on the same hypothesis — a second guess from the "
            "same reasoning is usually the same guess.")
    else:
        out["action"] = (
            f"Progress: {len(fixed)} fixed, {len(still)} still failing. "
            f"Keep going.")
    if not p["parsed"] and rc != 0:
        out["parse_warning"] = (
            "Could not parse the test output, so names are unavailable and "
            "this verdict rests on the exit code alone. Read `tail`.")
    return out


def baseline_status() -> Dict[str, Any]:
    if not _BASELINE:
        return {"ok": True, "have_baseline": False,
                "hint": "Run the tests and call workspace_baseline BEFORE editing."}
    return {"ok": True, "have_baseline": True, "baseline": _BASELINE}


def health() -> Dict[str, Any]:
    """Cheap static sanity sweep of the open repo — no scanners needed.

    Deliberately NARROW: only things that are close to always-wrong, so the
    output stays worth reading. A checker that reports fifty style opinions
    trains the operator to ignore it, and then it reports a real bug on
    line 51 and he ignores that too.
    """
    try:
        root = _require()
        issues: List[Dict[str, Any]] = []
        py_files = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                rel = os.path.relpath(os.path.join(dirpath, fn), root)
                if _skip_path(rel):
                    continue
                py_files += 1
                fp = os.path.join(dirpath, fn)
                try:
                    with open(fp, "r", encoding="utf-8", errors="replace") as f:
                        src = f.read()
                except OSError:
                    continue
                try:
                    tree_ = ast.parse(src, rel)
                except SyntaxError as e:
                    issues.append({"path": rel, "line": e.lineno,
                                   "kind": "syntax-error",
                                   "detail": str(e.msg),
                                   "severity": "high"})
                    continue
                for node in ast.walk(tree_):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        for d in (node.args.defaults
                                  + [x for x in node.args.kw_defaults if x]):
                            if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                                issues.append({
                                    "path": rel, "line": node.lineno,
                                    "kind": "mutable-default",
                                    "detail": f"{node.name}() has a mutable "
                                              f"default; it is shared across "
                                              f"every call",
                                    "severity": "high"})
                    if isinstance(node, ast.ExceptHandler) and node.type is None:
                        issues.append({
                            "path": rel, "line": node.lineno,
                            "kind": "bare-except",
                            "detail": "bare `except:` also swallows "
                                      "KeyboardInterrupt and SystemExit",
                            "severity": "medium"})
                    if isinstance(node, ast.Call) and isinstance(
                            node.func, ast.Attribute):
                        if (getattr(node.func.value, "id", "") == "subprocess"
                                and node.func.attr in ("run", "call",
                                                       "check_output",
                                                       "check_call")):
                            if not any(k.arg == "timeout"
                                       for k in node.keywords):
                                issues.append({
                                    "path": rel, "line": node.lineno,
                                    "kind": "subprocess-no-timeout",
                                    "detail": "can hang forever",
                                    "severity": "medium"})
                    if isinstance(node, ast.Compare) and len(node.ops) == 1:
                        if isinstance(node.ops[0], (ast.Is, ast.IsNot)) and \
                                isinstance(node.comparators[0], ast.Constant) \
                                and isinstance(node.comparators[0].value,
                                               (str, int)) \
                                and node.comparators[0].value is not None:
                            issues.append({
                                "path": rel, "line": node.lineno,
                                "kind": "is-with-literal",
                                "detail": "`is` on a literal compares "
                                          "identity, not value — works by "
                                          "accident via interning",
                                "severity": "medium"})
        order = {"high": 0, "medium": 1, "low": 2}
        issues.sort(key=lambda i: (order.get(i["severity"], 3), i["path"]))
        return {"ok": True, "python_files": py_files,
                "issue_count": len(issues), "issues": issues[:150],
                "truncated": len(issues) > 150,
                "note": ("Static heuristics on the open repo — real bugs, but "
                         "not a substitute for running the tests.")}
    except ContainmentError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
