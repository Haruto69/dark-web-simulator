"""Machine-readable Docker containment checks.

The same measured properties ``tests/test_docker_containment.py`` asserts, but
producing a *record* per check instead of a pass/fail assertion, so the results
can be exported to JSON/CSV and cited.

Every probe here is either a read of container configuration or a benign
operation that is expected to fail. Nothing attempts to escape, escalate, or
attack anything, and the container has no network, so a network probe cannot
reach a third party even in principle.

SCOPE OF WHAT THESE RESULTS SUPPORT
-----------------------------------
They record that the declared Docker options were applied on this host and that
a small set of benign operations failed as expected. They are not a security
audit, not an adversarial evaluation, and support no claim of production-grade
containment on any platform other than the one named in the run profile.
"""

import json
import uuid

CHECKS = (
    # (id, category, what it establishes)
    ("network_none", "configuration", "container network mode is 'none'"),
    ("read_only_rootfs", "configuration", "root filesystem is read-only"),
    ("tmpfs_workspace", "configuration", "/workspace is a tmpfs, not a host path"),
    ("workspace_noexec_nosuid", "configuration", "workspace tmpfs carries noexec and nosuid"),
    ("non_root_uid", "configuration", "container process runs as uid 10001"),
    ("capabilities_dropped", "configuration", "all Linux capabilities dropped"),
    ("no_new_privileges", "configuration", "no-new-privileges is set"),
    ("not_privileged", "configuration", "container is not privileged"),
    ("no_host_mounts", "configuration", "no bind mount or named volume"),
    ("no_docker_socket", "configuration", "no Docker socket inside the container"),
    ("memory_limit", "configuration", "memory limit applied"),
    ("pid_limit", "configuration", "PID limit applied"),
    ("ownership_label", "configuration", "container carries the ownership label"),
    ("blocked_network_probe", "probe", "outbound TCP connect fails"),
    ("blocked_dns_probe", "probe", "DNS resolution fails"),
    ("blocked_rootfs_write", "probe", "writes outside /workspace fail"),
    ("workspace_writable", "probe", "/workspace itself is writable"),
    ("blocked_capability_use", "probe", "a dropped capability cannot be used"),
    ("no_host_filesystem", "probe", "no host filesystem path is visible"),
    ("blocked_invalid_target", "probe", "the scenario tool rejects out-of-workspace targets"),
    ("blocked_unknown_filename", "probe", "an unknown filename inside the workspace is rejected"),
    ("cross_sandbox_isolation", "probe", "one sandbox cannot see another's workspace"),
)

CHECK_DESCRIPTIONS = {check_id: (category, description)
                      for check_id, category, description in CHECKS}

EXPECTED_MEMORY_BYTES = 256 * 1024 * 1024
EXPECTED_PID_LIMIT = 128
EXPECTED_UID = "10001"


def _result(check_id, passed, observed, expected):
    category, description = CHECK_DESCRIPTIONS[check_id]
    return {"check": check_id, "category": category, "description": description,
            "passed": bool(passed), "expected": str(expected),
            "observed": str(observed)[:500]}


def _inspect(backend, sandbox_id):
    raw = backend._run(["inspect", "--", backend._container(sandbox_id)]).stdout
    return json.loads(raw)[0]


def _exec(backend, sandbox_id, *argv):
    return backend._run(["exec", "--", backend._container(sandbox_id)] + list(argv),
                        check=False)


def _configuration_checks(backend, sandbox_id, config):
    host = config["HostConfig"]
    network = config.get("NetworkSettings") or {}
    tmpfs = host.get("Tmpfs") or {}
    workspace_flags = tmpfs.get("/workspace", "")
    mounts = config.get("Mounts") or []
    serialised = json.dumps(config)

    uid_probe = _exec(backend, sandbox_id, "python", "-c",
                      "import os;print(os.getuid())").stdout.strip()
    mount_table = _exec(backend, sandbox_id, "cat", "/proc/mounts").stdout
    workspace_line = next((line for line in mount_table.splitlines()
                           if " /workspace " in line), "")

    yield _result("network_none",
                  host.get("NetworkMode") == "none"
                  and list(network.get("Networks") or []) == ["none"]
                  and not network.get("IPAddress") and not network.get("Ports"),
                  "NetworkMode=%s networks=%s ip=%r"
                  % (host.get("NetworkMode"), list(network.get("Networks") or []),
                     network.get("IPAddress")),
                  "NetworkMode=none, no address, no ports")

    yield _result("read_only_rootfs", host.get("ReadonlyRootfs") is True,
                  host.get("ReadonlyRootfs"), True)

    yield _result("tmpfs_workspace",
                  "/workspace" in tmpfs and workspace_line.startswith("tmpfs "),
                  "tmpfs_opts=%r; /proc/mounts=%r" % (workspace_flags, workspace_line),
                  "/workspace mounted as tmpfs")

    yield _result("workspace_noexec_nosuid",
                  "noexec" in workspace_line and "nosuid" in workspace_line,
                  workspace_line, "noexec,nosuid present in /proc/mounts")

    yield _result("non_root_uid",
                  config["Config"].get("User") == "10001:10001"
                  and uid_probe == EXPECTED_UID,
                  "Config.User=%s runtime_uid=%s"
                  % (config["Config"].get("User"), uid_probe),
                  "10001:10001")

    yield _result("capabilities_dropped",
                  host.get("CapDrop") == ["ALL"] and not host.get("CapAdd"),
                  "CapDrop=%s CapAdd=%s" % (host.get("CapDrop"), host.get("CapAdd")),
                  "CapDrop=[ALL], CapAdd empty")

    yield _result("no_new_privileges",
                  "no-new-privileges" in (host.get("SecurityOpt") or []),
                  host.get("SecurityOpt"), "no-new-privileges present")

    yield _result("not_privileged", host.get("Privileged") is False,
                  host.get("Privileged"), False)

    yield _result("no_host_mounts",
                  not host.get("Binds") and not host.get("VolumesFrom")
                  and all(m.get("Type") != "bind" for m in mounts)
                  and (host.get("NetworkMode") != "host")
                  and (host.get("PidMode") or "") != "host"
                  and (host.get("IpcMode") or "") != "host",
                  "Binds=%s VolumesFrom=%s mount_types=%s PidMode=%r IpcMode=%r"
                  % (host.get("Binds"), host.get("VolumesFrom"),
                     [m.get("Type") for m in mounts], host.get("PidMode"),
                     host.get("IpcMode")),
                  "no binds, no volumes, no shared host namespace")

    socket_probe = _exec(backend, sandbox_id, "python", "-c",
                         "import os;print(os.path.exists('/var/run/docker.sock'))")
    yield _result("no_docker_socket",
                  "docker.sock" not in serialised
                  and socket_probe.stdout.strip() == "False",
                  "in_config=%s in_container=%s"
                  % ("docker.sock" in serialised, socket_probe.stdout.strip()),
                  "absent from config and from the container")

    yield _result("memory_limit", host.get("Memory") == EXPECTED_MEMORY_BYTES,
                  host.get("Memory"), EXPECTED_MEMORY_BYTES)
    yield _result("pid_limit", host.get("PidsLimit") == EXPECTED_PID_LIMIT,
                  host.get("PidsLimit"), EXPECTED_PID_LIMIT)

    labels = config["Config"].get("Labels") or {}
    yield _result("ownership_label", labels.get("dws-sandbox") == "1",
                  labels.get("dws-sandbox"), "dws-sandbox=1")


def _probe_checks(backend, sandbox_id):
    tcp = _exec(backend, sandbox_id, "python", "-c",
                "import socket;socket.create_connection(('1.1.1.1',53),3)")
    yield _result("blocked_network_probe", tcp.returncode != 0,
                  "exit=%s stderr=%s" % (tcp.returncode,
                                         (tcp.stderr or "").strip()[:160]),
                  "non-zero exit (connection impossible)")

    dns = _exec(backend, sandbox_id, "python", "-c",
                "import socket;socket.gethostbyname('example.com')")
    yield _result("blocked_dns_probe", dns.returncode != 0,
                  "exit=%s" % dns.returncode, "non-zero exit")

    write_results = {}
    for path in ("/etc/probe", "/opt/simulator/probe", "/probe"):
        write_results[path] = _exec(
            backend, sandbox_id, "python", "-c",
            "open(%r,'w').write('x')" % path).returncode
    yield _result("blocked_rootfs_write",
                  all(code != 0 for code in write_results.values()),
                  write_results, "every write outside /workspace fails")

    workspace_write = _exec(backend, sandbox_id, "python", "-c",
                            "open('/workspace/.probe','w').write('x')")
    yield _result("workspace_writable", workspace_write.returncode == 0,
                  "exit=%s" % workspace_write.returncode, "exit 0")

    raw_socket = _exec(backend, sandbox_id, "python", "-c",
                       "import socket;socket.socket(socket.AF_INET,socket.SOCK_RAW,1)")
    chown = _exec(backend, sandbox_id, "python", "-c",
                  "import os;os.chown('/etc/hostname',10001,10001)")
    yield _result("blocked_capability_use",
                  raw_socket.returncode != 0 and chown.returncode != 0,
                  "raw_socket_exit=%s chown_exit=%s"
                  % (raw_socket.returncode, chown.returncode),
                  "both non-zero (CAP_NET_RAW and CAP_CHOWN dropped)")

    host_fs = _exec(backend, sandbox_id, "python", "-c",
                    "import os;print([p for p in ('/host','/mnt/c','/c')"
                    " if os.path.exists(p)])")
    yield _result("no_host_filesystem", host_fs.stdout.strip() == "[]",
                  host_fs.stdout.strip(), "[]")

    rejected = {}
    for hostile in ("../../etc/passwd", "/etc/passwd", "nested/dir/file.txt"):
        probe = _exec(backend, sandbox_id, "python", "-m",
                      "sandbox.tools.impact_tool", "impact", "--", hostile)
        try:
            rejected[hostile] = json.loads(probe.stdout)[0]["status"]
        except (ValueError, IndexError, KeyError):
            rejected[hostile] = "unparseable"
    yield _result("blocked_invalid_target",
                  all(status == "rejected" for status in rejected.values()),
                  rejected, "every out-of-workspace target rejected")

    _exec(backend, sandbox_id, "python", "-c",
          "open('/workspace/not_in_dataset.txt','w').write('x')")
    unknown = _exec(backend, sandbox_id, "python", "-m",
                    "sandbox.tools.impact_tool", "impact", "--",
                    "not_in_dataset.txt")
    try:
        unknown_status = json.loads(unknown.stdout)[0]["status"]
    except (ValueError, IndexError, KeyError):
        unknown_status = "unparseable"
    yield _result("blocked_unknown_filename", unknown_status == "rejected",
                  unknown_status, "rejected")


def _cross_sandbox_check(backend):
    """Two live sandboxes: neither can observe the other's workspace."""
    first = "contain-a-%s" % uuid.uuid4().hex[:8]
    second = "contain-b-%s" % uuid.uuid4().hex[:8]
    backend.create(first)
    try:
        backend.create(second)
        try:
            marker = "marker-%s" % uuid.uuid4().hex[:8]
            _exec(backend, first, "python", "-c",
                  "open('/workspace/%s','w').write('x')" % marker)
            listing = _exec(backend, second, "python", "-c",
                            "import os,json;print(json.dumps(sorted(os.listdir('/workspace'))))")
            try:
                second_files = json.loads(listing.stdout)
            except ValueError:
                second_files = ["<unparseable>"]

            backend.run_impact(first, None)
            first_state = [f["status"] for f in backend.workspace_state(first)]
            second_state = [f["status"] for f in backend.workspace_state(second)]

            passed = (marker not in second_files
                      and all(s == "impacted" for s in first_state)
                      and all(s == "baseline" for s in second_state))
            return _result(
                "cross_sandbox_isolation", passed,
                "marker_visible_in_b=%s a_states=%s b_states=%s"
                % (marker in second_files, sorted(set(first_state)),
                   sorted(set(second_state))),
                "marker invisible; A impacted; B still baseline")
        finally:
            backend.destroy(second)
    finally:
        backend.destroy(first)


def run_containment_checks(backend):
    """Run every check against freshly created sandboxes. Always cleans up.

    Returns a list of result records. A check that raises is recorded as a
    failure with the exception text -- an error is never quietly dropped, and
    never converted into a pass.
    """
    results = []
    sandbox_id = "contain-%s" % uuid.uuid4().hex[:8]
    backend.create(sandbox_id)
    try:
        config = _inspect(backend, sandbox_id)
        for generator in (_configuration_checks(backend, sandbox_id, config),
                          _probe_checks(backend, sandbox_id)):
            while True:
                try:
                    results.append(next(generator))
                except StopIteration:
                    break
                except Exception as exc:  # noqa: BLE001 - recorded, not hidden
                    results.append({"check": "<error>", "category": "error",
                                    "description": "check raised",
                                    "passed": False, "expected": "no exception",
                                    "observed": "%s: %s" % (type(exc).__name__, exc)})
                    break
    finally:
        backend.destroy(sandbox_id)

    try:
        results.append(_cross_sandbox_check(backend))
    except Exception as exc:  # noqa: BLE001
        results.append({"check": "cross_sandbox_isolation", "category": "probe",
                        "description": CHECK_DESCRIPTIONS[
                            "cross_sandbox_isolation"][1],
                        "passed": False, "expected": "isolated",
                        "observed": "%s: %s" % (type(exc).__name__, exc)})
    return results


def summarise_containment(results):
    """Counts plus the ids of any check that did not pass."""
    failed = [r["check"] for r in results if not r["passed"]]
    missing = sorted(set(CHECK_DESCRIPTIONS) - {r["check"] for r in results})
    return {
        "checks_run": len(results),
        "checks_declared": len(CHECK_DESCRIPTIONS),
        "passed": sum(1 for r in results if r["passed"]),
        "failed": len(failed),
        "failed_checks": failed,
        "not_run": missing,
        "all_passed": not failed and not missing,
    }
