# Anonymous — Write‑Up
- Category: Enumeration / Privilege Escalation  
- Difficulty: Medium  
- CTF / Lab: Anonymous (TryHackMe)  
- Target: <IP> redacted  
- Date: 2025-12-19

## TL;DR
An externally accessible anonymous FTP service exposes a world‑writable `/scripts` directory. A script in that directory executes automatically and yields a shell as `namelessone`. Local enumeration reveals a SUID misconfiguration on `/usr/bin/env`, which is abused to obtain a root shell. Both user and root flags are recovered; flags are redacted in this public write‑up per TryHackMe policy and represented as MD5 hashes.

## Scope & Approach
- **Scope:** Single lab host <IP> redacted (TryHackMe)  
- **Techniques:** Service discovery, verification of anonymous upload vector, evidence capture, local privilege enumeration  
- **Tools:** nmap, FTP/SMB enumeration, LinEnum/find, netcat listener  
- **Note:** This is a concise write‑up (findings, impact, evidence pointers, remediation) — not a step‑by‑step walkthrough.

## Executive Impact Summary
Combined insecure public services (anonymous FTP + writable script location) and a local SUID misconfiguration result in a remote‑to‑root compromise. In production, this pattern is classified as **critical** due to potential for complete system takeover and data exposure.

## Findings

### 1) Anonymous FTP with world‑writable scripts directory — High
- **Summary:** Anonymous FTP allows login and exposes a `scripts` directory with world‑writable permissions.  
- **Impact:** Attackers can upload executable files that may be processed by system tasks, enabling remote code execution.  
- **Evidence (excerpt):**  
  - nmap: `21/tcp open ftp – vsftpd 2.0.8 or later`  
  - NSE: `drwxrwxrwx ... scripts [NSE: writeable]`  
  - FTP banner: `220 NamelessOne's FTP Server!` → `230 Login successful`  
  - FTP listing: `-rwxr-xrwx ... clean.sh`

### 2) Script execution produces interactive shell — High
- **Summary:** A script in `/scripts` executes and produces a reverse connection to the tester’s listener, yielding a `namelessone` shell.  
- **Impact:** Execution of attacker‑controlled content from a writable directory provides direct RCE as a local user.  
- **Evidence (excerpt):**  
  - Netcat log: `connect to [...]` → prompt `namelessone@anonymous:~$`

### 3) SUID misconfiguration: /usr/bin/env — Critical
- **Summary:** `/usr/bin/env` is present with the SUID bit set. It is abused to spawn a privileged shell, escalating from `namelessone` to root.  
- **Impact:** SUID binaries that execute shells are common and effective privilege escalation vectors.  
- **Evidence (excerpt):**  
  - LinEnum/find: `/usr/bin/env — possible SUID`  
  - Escalation proof: root prompt and `/root/root.txt` accessed (flag redacted; MD5 stored privately).

### 4) SMB exposure aids user discovery — Medium
- **Summary:** SMB shares are publicly enumeratable and leak user and path information, including `namelessone`.  
- **Impact:** SMB leaks usernames and filesystem layout, aiding privilege escalation or lateral movement.  
- **Evidence (excerpt):**  
  - Share listing: `\\<IP> redacted\pics` — Anonymous access: READ  
  - User enumeration: `namelessone` (RID 1003)

## Evidence & Artifacts
- `nmap_summary.txt` — condensed nmap findings (21/ftp, 22/ssh, 139/445 Samba).  
- `ftp_scripts_listing.txt` — FTP listing showing `scripts` and `clean.sh`.  
- `clean_sh_contents.txt` / `clean_sh_md5.txt` — sanitized script contents and MD5 hash.  
- `nc_shell.log` — listener capture showing `namelessone` shell.  
- `smb_enum.txt` — SMB enumeration output.  
- `suid_list.txt` — SUID discovery highlighting `/usr/bin/env`.  
- `linenum_summary.txt` — local enumeration summary.  
- `root_proof.txt` — root shell proof; flag redacted, MD5 stored privately.

## Note on Sensitive Data
Flags and exploit payloads are redacted. TryHackMe flags are represented as MD5 values for verification. Full payloads and raw flags are stored privately for audit purposes.

## Remediation

**Immediate**
- Disable anonymous FTP logins.  
- Remove unnecessary SUID bits (e.g., `/usr/bin/env`).  

**Short Term**
- Prevent automated tasks from executing content in world‑writable directories.  
- Harden SMB: disable guest access, enforce authentication, apply least privilege.  

**Long Term**
- Implement file integrity monitoring for upload directories.  
- Regularly audit SUID/SGID files.  
- Adopt secure deployment practices for services accepting user content.

## Lessons Learned
- Legacy services like FTP and SMB remain high‑risk if misconfigured.  
- Writable directories processed by system tasks create severe risk.  
- SUID misconfigurations are low‑effort, high‑impact escalation paths.  
- Consistent documentation with evidence excerpts strengthens reproducibility.

## Appendix (Private Audit)
Full logs, transcripts, scripts, and raw artifacts are stored privately. Public report contains only redacted excerpts and MD5 hashes.

## Acknowledgements
Prepared from testing notes and captured evidence during the TryHackMe lab session. Flags and payloads redacted to comply with TryHackMe guidelines.
