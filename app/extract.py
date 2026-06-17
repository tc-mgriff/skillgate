"""
Safe extraction of untrusted .skill / .zip bundles.

A .skill file is a zip. Uploaders are untrusted, so extraction is the most
dangerous step in the pipeline. This module refuses to write anything to disk
until every entry has passed the defenses below. It NEVER executes anything
from the bundle; the downstream scanner only reads files as text.

Defenses enforced here:
  - path traversal / zip-slip   (entries resolving outside the dest dir)
  - absolute-path entries
  - symlink entries             (rejected outright; they can point anywhere)
  - zip bombs                   (total uncompressed size + decompression ratio)
  - entry-count explosion
  - oversized individual files

On ANY violation the whole bundle is rejected and the partial extraction is
removed. We fail closed.
"""

import os
import shutil
import zipfile
from dataclasses import dataclass, field

# --- limits (tune for your environment) -------------------------------------

MAX_ENTRIES = 2_000              # files in the archive
MAX_TOTAL_UNCOMPRESSED = 50 * 1024 * 1024   # 50 MB extracted total
MAX_FILE_UNCOMPRESSED = 25 * 1024 * 1024    # 25 MB per file (matches upload cap)
MAX_RATIO = 100                  # uncompressed/compressed; higher => likely bomb
S_IFLNK = 0o120000               # unix symlink mode bits


class UnsafeArchive(Exception):
    """Raised when a bundle violates a security rule (path traversal, symlink, zip bomb).
    These are hard-reject signals — the bundle cannot be trusted."""


class OversizedArchive(UnsafeArchive):
    """Raised when a bundle exceeds a resource cap (file too large, too many entries,
    total size). Not a security signal — the bundle is probably fine but can't be
    processed within the configured limits."""


@dataclass
class ExtractResult:
    dest: str
    file_count: int
    total_bytes: int
    entries: list = field(default_factory=list)


def _is_within(base, target):
    """True iff `target` resolves inside `base`."""
    base = os.path.realpath(base)
    target = os.path.realpath(target)
    return target == base or target.startswith(base + os.sep)


def safe_extract_zip(zip_path, dest_dir):
    """Extract `zip_path` into `dest_dir`, enforcing all defenses.
    Returns ExtractResult on success; raises UnsafeArchive on any violation."""
    os.makedirs(dest_dir, exist_ok=True)

    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as e:
        raise UnsafeArchive(f"not a valid zip: {e}") from e

    with zf:
        infos = zf.infolist()

        if len(infos) > MAX_ENTRIES:
            raise OversizedArchive(
                f"too many entries: {len(infos)} > {MAX_ENTRIES}")

        total_unc = sum(i.file_size for i in infos)
        total_comp = sum(i.compress_size for i in infos) or 1
        if total_unc > MAX_TOTAL_UNCOMPRESSED:
            raise OversizedArchive(
                f"uncompressed size {total_unc} exceeds "
                f"{MAX_TOTAL_UNCOMPRESSED}")
        if total_unc / total_comp > MAX_RATIO:
            raise UnsafeArchive(
                f"decompression ratio {total_unc/total_comp:.0f}x exceeds "
                f"{MAX_RATIO}x (possible zip bomb)")

        # pre-flight: validate EVERY entry before writing ANY of them
        for info in infos:
            name = info.filename
            norm = name.replace("\\", "/")

            if norm.startswith("/") or os.path.isabs(norm):
                raise UnsafeArchive(f"absolute path entry: {name}")
            if ".." in norm.split("/"):
                raise UnsafeArchive(f"path traversal entry: {name}")

            mode = info.external_attr >> 16
            if mode and (mode & 0o170000) == S_IFLNK:
                raise UnsafeArchive(f"symlink entry rejected: {name}")

            if info.file_size > MAX_FILE_UNCOMPRESSED:
                raise OversizedArchive(
                    f"file too large: {name} ({info.file_size} bytes)")

            target = os.path.join(dest_dir, norm)
            if not _is_within(dest_dir, target):
                raise UnsafeArchive(f"entry escapes destination: {name}")

        # all entries validated; now extract
        extracted = []
        try:
            for info in infos:
                norm = info.filename.replace("\\", "/")
                target = os.path.join(dest_dir, norm)
                if info.is_dir() or norm.endswith("/"):
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                # stream-copy with a hard cap so a lying header can't blow memory
                with zf.open(info, "r") as src, open(target, "wb") as dst:
                    written = 0
                    while True:
                        chunk = src.read(65536)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > MAX_FILE_UNCOMPRESSED:
                            raise OversizedArchive(
                                f"file exceeded size cap during read: {norm}")
                        dst.write(chunk)
                extracted.append(norm)
        except Exception:
            shutil.rmtree(dest_dir, ignore_errors=True)
            raise

    return ExtractResult(
        dest=dest_dir,
        file_count=len(extracted),
        total_bytes=total_unc,
        entries=extracted,
    )
