# Lunizz CTF — Write‑Up

- Category: Enumeration / Privilege Escalation  
- Difficulty: Medium  
- CTF / Lab: Lunizz CTF (TryHackMe)  
- Target: <IP redacted>  
- Date: 2025-12-23

## TL;DR
A reachable MySQL instance allowed changing an application control flag which caused the web app to expose a "Command Executer" form. That form (evaluating database-controlled input) gave a shell as the webserver user. Local enumeration found a bcrypt hash that required base64 preprocessing to crack; the recovered password allowed SSH access. A local privileged backdoor service enabled changing another local account's password and escalating to root. Flags and credentials are omitted from this public write‑up.

## Scope & Approach
- Single host assessment (internal lab).  
- Techniques: service enumeration, DB access, web interface abuse, offline hash cracking (with preprocessing), local privilege escalation.  
- Tools (representative): `nmap`, `mysql` client, `curl`, Python 3 + `bcrypt`, `ssh`.

## Key Findings (condensed)
- MySQL accepted a known/dev account and allowed modifying application state — this was used to enable a privileged web feature.  
- The web app executed/evaluated data originating from the database, resulting in remote code execution as the webserver user.  
- A bcrypt hash on disk corresponded to bcrypt(base64(password)). Cracking required base64-encoding candidates before bcrypt-checking.  
- The cracked credential provided SSH access.  
- A localhost-only backdoor service accepted POST requests (parameters: password, cmdtype) and provided privileged operations (including changing a local account password) — this led to `su` → root.

Note: Sensitive values (usernames, passwords, flag contents, and full exploit code) are intentionally omitted.

## Important Commands (only the essential, non-sensitive ones)
- MySQL (connect and flip the application flag; replace placeholders before use):
```bash
mysql -u <db-user> -p -h <IP> -P 3306 --skip-ssl
# In mysql:
USE <app-db>;
UPDATE <control-table> SET <flag-column>=1 WHERE <flag-column>=0;
```

- Interact with web Command Executer (high level — use the browser form):
  - Visit the exposed page and submit commands through the form after enabling the flag.

- Crack bcrypt(hash(base64(password))) — representative script (stored hash redacted):
```python
#!/usr/bin/env python3
import bcrypt, base64

stored_hash = b"$2b$12$<REDACTED_HASH>"

with open("/usr/share/wordlists/rockyou.txt", "r", encoding="latin-1", errors="ignore") as f:
    for w in f:
        pw = w.strip()
        if not pw:
            continue
        candidate = base64.b64encode(pw.encode("ascii", "ignore"))
        if bcrypt.checkpw(candidate, stored_hash):
            print("Cracked:", pw)
            break
```

- Change local account password via localhost backdoor (example; send from local shell on the box):
```bash
curl -X POST -d "password=<new-password>&cmdtype=passwd" http://127.0.0.1:8080/
```

- SSH into the host (use the cracked password):
```bash
ssh <user>@<IP>
```

## Alternative escalation note
- You can check `sudo --version` on the target to determine whether the installed sudo build might be vulnerable; investigating that is an alternate escalation path. This report does not include exploit code.

## Remediation (prioritized)
- Restrict remote DB access and enforce strong, unique database credentials.  
- Never execute or evaluate application data as code — validate/sanitize and separate state from executable logic.  
- Remove undocumented or backdoor services bound to loopback (or protect them with strict authentication and logging).  
- Avoid non-standard/transformed password storage patterns; use well-known schemes and document any transforms.  
- Harden authentication (SSH keys / 2FA), minimize sudo access, and keep packages patched.
