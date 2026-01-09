# 🧩 CMesS — Write‑Up

- Category: Enumeration / Privilege Escalation  
- Difficulty: Medium  
- CTF / Lab: CMesS (TryHackMe)  
- Target: <IP redacted>  
- Date: 2026-01-07  

---

## TL;DR
Enumeration revealed **Gila CMS** running on the target. Subdomain fuzzing uncovered a hidden **dev** portal, which after mapping in `/etc/hosts` exposed the admin dashboard. Valid credentials confirmed the CMS version as **1.10.9**, vulnerable to an authenticated RCE exploit. Exploiting this yielded a shell as `www-data`. Local enumeration uncovered a backup file leaking credentials for `andre`, enabling SSH access. A cron‑driven tar job was then abused to create a root‑owned SUID binary, escalating privileges to root and retrieving the final flag.  

---

## Scope & Approach
- **Scope:** Single host assessment (internal lab).  
- **Techniques:** Web enumeration, subdomain discovery, authenticated RCE, credential reuse, cron/tar abuse.  
- **Tools:** Nmap, Gobuster, Wfuzz, Exploit‑DB, Netcat, SSH.  

---

## Attack Narrative
1. **Initial Recon:**  
   Service discovery showed SSH and Apache. The webserver banner and `robots.txt` hinted at **Gila CMS** with restricted directories.

2. **Directory & Subdomain Discovery:**  
   Gobuster revealed common endpoints like `/login`, `/admin`, and `/api`. Wfuzz uncovered multiple subdomains, with a filtered run isolating **`dev`**. Adding `dev.cmess.thm` to `/etc/hosts` unlocked access to the dev portal.

3. **Admin Portal & Version Identification:**  
   The dev portal exposed admin credentials. Logging in confirmed the CMS version as **1.10.9**, a build with a known authenticated RCE.

4. **Exploitation:**  
   Leveraging Exploit‑DB’s authenticated RCE (ID 51569) provided remote code execution, dropping a shell as `www-data`.

5. **Credential Reuse:**  
   Local enumeration uncovered `/opt/.password.bak`, leaking credentials for **andre**. SSH access was achieved with these credentials.

6. **Privilege Escalation:**  
   Cron analysis revealed a backup job running tar every two minutes in `/home/andre/backup`. By abusing tar’s `--checkpoint` and `--checkpoint-action` options, a payload was executed that created a root‑owned SUID bash binary. Running it escalated privileges to root.

7. **Objective:**  
   With root access, the final flag was retrieved from `/root/root.txt`. (Flag redacted.)

---

## Key Insights
- **Dev subdomains** often expose admin surfaces and version details — fuzzing them is critical.  
- **Authenticated RCE** remains a decisive exploit when credentials are exposed via misconfigurations.  
- **Backup artifacts** (`*.bak`) are high‑value targets; they frequently leak sensitive credentials.  
- **Cron + tar abuse** is a classic escalation vector, still effective when backups run as root.  

---

## Remediation
- Patch Gila CMS to a secure version and remove exposed dev portals from production.  
- Enforce strong, unique credentials; avoid storing plaintext or weakly protected backups.  
- Audit cron jobs; avoid unsafe tar options and run backups with least privilege.  
- Restrict SUID binaries and monitor for unexpected creations in `/tmp`.  
- Implement host‑based monitoring and alerting for admin logins and cron anomalies.  
