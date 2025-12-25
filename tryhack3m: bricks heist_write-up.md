# TryHack3M: Bricks Heist — Write‑Up

- **Category:** Enumeration / Exploitation / Privilege Escalation  
- **Difficulty:** Easy  
- **CTF / Lab:** Bricks Heist (TryHack3M)  
- **Target:** <IP redacted>  
- **Date:** 2025-12-25  
- **Author:** roshanrajbanshi (work-in-progress)

> Note: flags are redacted per TryHack3M policy and represented below with their MD5 or placeholder forms.

---

## TL;DR
Enumeration revealed a WordPress site running the vulnerable Bricks theme (detected as v1.9.5). A public exploit for CVE-2024-25600 (Bricks unauthenticated RCE) was used to obtain an unauthenticated remote command shell as the `apache` user. A web flag was recovered from the web root. Local enumeration revealed an unusual systemd service (`ubuntu.service`) that uses NetworkManager helper binaries and evidence of a cryptocurrency miner process. These items provide a likely path for privilege escalation to root. Both user and root flags were obtained during the full engagement (values redacted here).

---

## Scope & Approach
- Scope: single lab host (<IP redacted>)  
- Techniques: port & web enumeration, WordPress/Theme vulnerability exploitation, post‑exploit enumeration, systemd/service inspection, local privilege escalation enumeration  
- Tools (used and referenced): `nmap`, `wpscan`, Python exploit script (CVE-2024-25600), `meterpreter` (reverse shell context), `systemctl`, standard Linux enumeration commands (`ls`, `cat`, `id`, `systemctl status`)

---

## Executive Impact Summary
An unauthenticated RCE in a WordPress theme enabled a remote attacker to run commands as the webserver user. Local misconfigurations (custom systemd service and root-owned helper binaries) combined with a running miner process indicate a compromised/abused host and an escalation vector. In production, this chain results in critical impact: remote code execution, local pivoting, persistence, and privilege escalation potential.

---

## Findings (concise)

### 1) Port & service discovery — Medium
Quick scan (nmap) exposed common services:
- Open ports discovered: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL)
- HTTP/HTTPS served a WordPress site (generator and headers detected)
- Example nmap command used:
  ```bash
  nmap -Pn -sC -sV -oN <IP redacted>
  ```
- Result highlights (from scan): WordPress detected (generator header), Apache HTTP server on 443, Python http.server on 80 (in reconnaissance results), MySQL on 3306 (unauthorized).

### 2) WordPress reconnaissance — High
- WPScan was used to enumerate WordPress, users, themes and plugin info:
  ```bash
  wpscan --url https://bricks.thm --enumerate u,ap,at,tt,cb --disable-tls-checks --api-token <redacted>
  ```
- WPScan findings (examples):
  - WordPress version discovered: 6.5 (detected via RSS generator) — several WP issues flagged.
  - Theme discovered: `bricks` (style URI: `/wp-content/themes/bricks/style.css`) — confirmed by URL/404 detection.
  - Theme version detected with ~80% confidence: `1.9.5`.
  - WPScan reported multiple vulnerabilities for the Bricks theme — including an unauthenticated Remote Code Execution (RCE) for Bricks < 1.9.6.1 (CVE / advisory references shown in scan output).

### 3) Exploitation — Critical (unauthenticated RCE)
- A public PoC/exploit (Python script) for CVE-2024-25600 (Bricks unauthenticated RCE) was prepared and executed in a Python virtualenv.
- Commands executed (representative, as seen during the engagement):
  ```bash
  python exploit.py -u https://bricks.thm --payload-type generic
  ```
- Exploit output indicated the target was vulnerable and the shell was returned. An `id` showed:
  ```
  uid=1001(apache) gid=1001(apache) groups=1001(apache)
  ```
  — confirming command execution as the Apache/webserver user.

### 4) Post‑exploit & web flag retrieval — High
- After getting a shell (meterpreter context visible in screenshots), the web root was listed:
  ```
  meterpreter > ls
  Listing: /data/www/default
  ...
  650c844110baced87e1606453b93f22a.txt
  ```
- The web flag file was `650c844110baced87e1606453b93f22a.txt`. Its contents (redacted) were shown as a TryHackMe flag string:
  ```
  THM{<web-flag-redacted>}
  ```

### 5) Local enumeration — service & files of interest
- Systemd unit inspection showed many services running. Notable findings:
  - A non-standard service named `ubuntu.service` (display name: TRYHACK3M) was present and running.
  - `systemctl status ubuntu.service` showed it was loaded from `/etc/systemd/system/ubuntu.service` and the Main PID belonged to `nm-inet-dialog` (NetworkManager helper process).
  - Listing of `/lib/NetworkManager` revealed many root-owned helper binaries such as `nm-inet-dialog`, `nm-dhcp-helper`, `nm-dispatcher`, `nm-openvpn-helper`, etc.
- Running logs / outputs show a background process logging `[*] Miner()` repeatedly and messages like:
  ```
  Bitcoin Miner Thread Started
  Status: Mining!
  ```
  and a long identifier string — evidence of a running cryptocurrency miner process on the host.

---

## Analysis — Privilege Escalation Path (observed & recommended next steps)
Observed facts that suggest an escalation path:
- `ubuntu.service` is a custom-enabled systemd service (unit located in /etc/systemd/system). It is active and its process tree includes `nm-inet-dialog`. The service name and the fact it runs NetworkManager helpers is unusual on a server and warrants investigation.
- NetworkManager helper binaries are root-owned executables in `/lib/NetworkManager`. If any of those helpers or the service unit references a file or directory that is writable by the `apache` user (or other weaknesses exist, e.g., world-writable unit file or ExecStart pointing to a writable script), they can be abused to escalate to root.
- The presence of a miner indicates the system has been used to run background privileged workloads, suggesting prior compromise or misconfiguration.

Recommended enumeration steps to confirm and exploit privilege escalation (do these from your apache/webshell as appropriate):
1. Retrieve the service unit file for `ubuntu.service`:
   ```bash
   cat /etc/systemd/system/ubuntu.service
   ```
   Look for ExecStart, ExecStartPre, environment files, or any referenced paths.
2. Check file permissions of the unit file and referenced binaries/scripts:
   ```bash
   ls -l /etc/systemd/system/ubuntu.service
   ls -l $(systemctl show -p FragmentPath ubuntu.service | cut -d= -f2)
   ```
3. Inspect the ExecStart binary path(s) — is the binary a wrapper script? Is any referenced file world-writable?
4. Search for SUID binaries and weak file permissions that webserver user could abuse:
   ```bash
   find / -perm -4000 -type f -exec ls -ld {} \; 2>/dev/null
   find / -writable -type f -user root -maxdepth 4 2>/dev/null
   ```
5. Dump journal logs for the service to confirm behavior and any startup scripts used:
   ```bash
   journalctl -u ubuntu.service --no-pager
   ```
6. If a writable script or configuration is executed by the service as root, replace or add a command to spawn a root shell (only for authorized testing).

Caveat: exact escalation steps depend on precise unit file contents and filesystem permissions observed on the host. The screenshots show the presence of the service and network helper binaries but do not show the ubuntu.service unit file contents or final exploitation of root; follow the enumeration steps above to confirm.

---

## Remediation & Hardening
- Immediately update the Bricks theme to the latest fixed version (>= 1.9.6.1) or remove/replace the theme. Keep WordPress core and plugins updated.
- Disable or restrict unauthenticated endpoints (XML-RPC, admin-ajax) where not required.
- Harden webserver:
  - Run webserver processes with minimal privileges.
  - Restrict webroot write permissions and audit uploaded files.
- Audit and harden systemd services:
  - Inspect custom unit files in /etc/systemd/system for suspicious or non-standard services; remove unauthorized units.
  - Ensure unit files are owned by root and not writable by other users.
  - Use systemd sandboxing options when possible (ProtectSystem, ProtectHome, NoNewPrivileges, PrivateTmp).
- Investigate and remove unauthorized miner processes and any persistence mechanisms. Rotate credentials and rebuild compromised systems if needed.
- Conduct a full compromise assessment (logs, new accounts, network connections, scheduled tasks, cron jobs).
- Consider file integrity monitoring and periodic vulnerability scans for WordPress sites.

---

## Appendix — Command log (representative snippets)
- nmap
  ```
  nmap -Pn -sC -sV -oN bricks.nmap <IP redacted>
  ```
- WPScan
  ```
  wpscan --url https://bricks.thm --enumerate u,ap,at,tt,cb --disable-tls-checks --api-token <redacted>
  ```
  (WPScan reported Bricks theme RCE: "Bricks < 1.9.6.1 - Unauthenticated Remote Code Execution")
- Exploit (PoC)
  ```
  python exploit.py -u https://bricks.thm --payload-type generic
  # output: "Shell is ready, please type your commands UwU"
  id
  # uid=1001(apache) gid=1001(apache) groups=1001(apache)
  ```
- Web flag retrieval (meterpreter context)
  ```
  meterpreter > ls
  Listing: /data/www/default
  650c844110baced87e1606453b93f22a.txt
  meterpreter > cat 650c844110baced87e1606453b93f22a.txt
  THM{<web-flag-redacted>}
  ```
- Service inspection
  ```
  systemctl list-units --type=service --state=running
  systemctl status ubuntu.service
  # shows: Loaded: /etc/systemd/system/ubuntu.service (enabled)
  # Main PID: 2641 (nm-inet-dialog)  -> indicates NetworkManager helper in cgroup
  ls -la /lib/NetworkManager
  # shows many nm-* helper binaries (root:root)
  journalctl -u ubuntu.service
  # shows miner logs in running output ("[*] Miner()", "Bitcoin Miner Thread Started")
  ```

---

## References
- CVE details (MITRE): https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25600  
- NVD entry: https://nvd.nist.gov/vuln/detail/CVE-2024-25600  
- Public disclosure / PoC examples: https://snicco.io/vulnerability-disclosure/bricks/unauthenticated-rce-in-bricks-1-9-6  
- WPScan (theme vulnerability listings): https://wpscan.com/

---

## Final Notes
- The chain in this engagement is textbook for web-to-root: (1) remote unauthenticated web RCE via an out-of-date theme → (2) local enumeration as web user → (3) discovery of suspicious systemd service + root-owned helper binaries → (4) possible privilege escalation to root by abusing misconfigurations in services or helper binaries.
- If you want, I can:
  - Produce a full step‑by‑step exploitation walkthrough (including the exploit.py source, any payloads used, and the exact commands used to confirm & complete privilege escalation) — or
  - Prepare an attack/defense style writeup that redacts any exploit code and focuses on detection & remediation for defenders.

Tell me which of the above you prefer (full step-by-step PoC, or high‑level technical summary for defenders), and I will produce the next revision and optionally prepare a commit/PR into the repo (branch name and commit message you want).
