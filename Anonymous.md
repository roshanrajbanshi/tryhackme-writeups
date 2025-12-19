# Anonymous
- **Category:** Enumeration / Privilege Escalation
- **Difficulty:** Medium
- **CTF / Lab:** Anonymous
- **Target:** 10.48.182.61
- **Date:** 2025-12-19

## 1. Challenge Description

Enumerate the machine and answer the following:

- How many ports are open?
- What service is running on port 21?
- What service is running on ports 139 and 445?
- There's a share on the user's computer. What's it called?
- Retrieve `user.txt` and `root.txt` flags.

## 2. Approach

- Run full Nmap scan with service and OS detection.
- Enumerate FTP and SMB shares.
- Explore writable FTP directory and upload reverse shell.
- Trigger shell via `clean.sh` script.
- Escalate privileges using SUID binary `/usr/bin/env`.

## 3. Exploitation

- **Nmap scan** revealed open ports: 21 (FTP), 22 (SSH), 139/445 (SMB).
- **FTP login** allowed anonymous access; writable `/scripts` directory found.
- Uploaded reverse shell via `clean.sh` with TCP payload to port 1234.
- Triggered shell and gained access as `namelessone`.
- Enumerated SUID binaries and found `/usr/bin/env` usable for escalation.
- Spawned root shell and accessed `/root/root.txt`.

## 4. Evidence

- Nmap scan showing open ports and service versions.
- FTP session logs confirming anonymous login and writable `/scripts`.
- `clean.sh` script with embedded reverse shell payload.
- Netcat listener receiving shell from target.
- SMB enumeration showing `pics` share and user `namelessone`.
- SUID scan listing `/usr/bin/env`.
- Privilege escalation output showing root shell and flag access.

## 5. Flags

- **user.txt:** Found in `/home/namelessone/user.txt`  
- **root.txt:** Found in `/root/root.txt`  
*Values redacted for documentation.*

## 6. Lessons Learned

- FTP misconfigurations can allow anonymous write access — always check for upload vectors.
- Scheduled or auto-executed scripts like `clean.sh` can be hijacked for reverse shells.
- SMB shares often leak usernames and directory paths — useful for lateral movement.
- SUID binaries like `/usr/bin/env` are classic escalation paths — always enumerate them.
- Documenting each step with screenshots and commands ensures reproducibility and clarity.
