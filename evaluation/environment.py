"""Formal experiment profile: the machine a measurement was actually taken on.

Every formal result file embeds this record. A latency number without the
runtime that produced it is not a reproducible result, and a container-sandbox
claim backed by a LocalBackend run would be a false one -- so the backend is
recorded verbatim and :func:`require_docker_backend` refuses to let a formal
run silently degrade.

Nothing here is inferred or defaulted: a field the machine cannot report is
recorded as ``None`` rather than guessed.
"""

import ctypes
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

#: The only backend a formal run may use. Section 3 of Milestone 4.
FORMAL_BACKEND = "docker"

DOCKER_TIMEOUT = 20


def _run(argv, timeout=DOCKER_TIMEOUT):
    """Run a command, returning stripped stdout, or None on any failure."""
    try:
        completed = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=timeout, shell=False, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def docker_desktop_version():
    """Docker *client* version -- what Docker Desktop ships on this host."""
    return _run(["docker", "version", "--format", "{{.Client.Version}}"])


def docker_engine_version():
    """Docker *server* (engine) version, inside Desktop's Linux VM."""
    return _run(["docker", "version", "--format", "{{.Server.Version}}"])


def docker_engine_os():
    return _run(["docker", "info", "--format",
                 "{{.OperatingSystem}} / {{.OSType}} / {{.Architecture}}"])


def image_identity(image):
    """``(image id, repo digest)`` for the target image, or ``(None, None)``.

    A local ``docker build`` produces no repo digest (nothing was pushed), so a
    missing digest is expected and is recorded as None rather than faked.
    """
    image_id = _run(["docker", "image", "inspect", "--format", "{{.Id}}",
                     "--", image])
    digests = _run(["docker", "image", "inspect", "--format",
                    "{{join .RepoDigests \",\"}}", "--", image])
    return image_id, (digests or None)


def git_commit():
    """The commit the measurement was taken at, plus whether the tree was dirty."""
    if shutil.which("git") is None:
        return None, None
    sha = _run(["git", "rev-parse", "HEAD"])
    status = _run(["git", "status", "--porcelain"])
    # ``status`` is None both when git fails and when the tree is clean, so
    # distinguish: a clean tree returns an empty string, which _run maps to None.
    dirty = None if sha is None else bool(status)
    return sha, dirty


def cpu_count():
    return os.cpu_count()


def _posix_total_memory_bytes():
    """Physical RAM in bytes via POSIX ``sysconf``, or None if unavailable."""
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (AttributeError, ValueError, OSError):
        return None


def _windows_total_memory_bytes():
    """Physical RAM in bytes via the Win32 ``GlobalMemoryStatusEx`` API.

    Standard-library only (``ctypes``): no subprocess, no third-party
    dependency, no network access. Returns None if the call fails.
    """
    class _MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    try:
        stat = _MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            return None
        return int(stat.ullTotalPhys)
    except (AttributeError, OSError, ValueError):
        return None


def total_memory_bytes():
    """Physical host RAM in bytes, or None if this platform will not say.

    ``os.sysconf`` covers POSIX; ``GlobalMemoryStatusEx`` covers Windows,
    where ``os.sysconf`` does not exist at all. Both paths measure the same
    quantity -- total physical memory of the host the measurement was taken
    on -- so the field's meaning does not change across platforms. This is
    independent of Docker: :func:`docker_memory_bytes` records the Linux VM's
    memory separately, and the two are never conflated.

    A result is only returned when it is a positive integer; anything else is
    treated as "this platform will not say" rather than guessed at.
    """
    if platform.system() == "Windows":
        value = _windows_total_memory_bytes()
    else:
        value = _posix_total_memory_bytes()
    if not isinstance(value, int) or value <= 0:
        return None
    return value


def docker_memory_bytes():
    raw = _run(["docker", "info", "--format", "{{.MemTotal}}"])
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def experiment_profile(backend, image=None, extra=None):
    """The full reproducibility record embedded in every formal result file."""
    image_id, repo_digest = (image_identity(image) if image else (None, None))
    sha, dirty = git_commit()
    profile = {
        "backend": backend,
        "experiment_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "experiment_timestamp_local": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "os": platform.platform(),
        "os_system": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor() or None,
        "python_version": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "cpu_count": cpu_count(),
        "host_memory_bytes": total_memory_bytes(),
        "docker_vm_memory_bytes": docker_memory_bytes(),
        "docker_desktop_client_version": docker_desktop_version(),
        "docker_engine_version": docker_engine_version(),
        "docker_engine_os": docker_engine_os(),
        "target_image": image,
        "target_image_id": image_id,
        "target_image_repo_digest": repo_digest,
        "git_commit": sha,
        "git_tree_dirty": dirty,
        "clock": "time.perf_counter",
    }
    if extra:
        profile.update(extra)
    return profile


class FormalRunError(RuntimeError):
    """A formal run cannot proceed under the conditions it requires."""


def require_docker_backend(backend_name, image):
    """Refuse to start a formal run on anything but a working Docker backend.

    Silent fallback to ``LocalBackend`` would attach container-isolation claims
    to measurements taken with no container at all, so this raises instead.
    """
    if backend_name != FORMAL_BACKEND:
        raise FormalRunError(
            "formal experiments run on the %r backend only; %r was requested"
            % (FORMAL_BACKEND, backend_name))
    if shutil.which("docker") is None:
        raise FormalRunError("the docker CLI is not on PATH")
    if docker_engine_version() is None:
        raise FormalRunError(
            "the Docker engine is not reachable; refusing to fall back to the "
            "local backend for a formal run")
    image_id, _ = image_identity(image)
    if image_id is None:
        raise FormalRunError(
            "target image %r is not present. Build it first:\n"
            "  docker build -t %s -f docker/sandbox-target/Dockerfile ."
            % (image, image))
    return True
