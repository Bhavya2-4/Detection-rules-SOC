# Detection Rule: GRIDTIDE Backdoor Activity Detection

## Overview
This detection rule identifies potential activity associated with the **GRIDTIDE backdoor**, a persistence-focused malware that may deploy hidden binaries, establish service persistence, and exfiltrate data using cloud services.

The rule focuses on identifying:

- Execution of suspicious binaries named **xapt**
- Persistence via **systemd service creation**
- Suspicious SSH-based activity performed by service accounts
- Encoded command execution patterns
- Suspicious communication with **Google Sheets APIs**, potentially used for command-and-control or data exfiltration

---

# Endpoint Detection Query (Elastic KQL)

```kql
(
process.command_line : (
"* /var/tmp/xapt*" OR
"*./xapt*" OR
"*nohup ./xapt*" OR
"*/usr/sbin/xapt*"
)
OR process.executable : (
"/var/tmp/xapt" OR
"/usr/sbin/xapt"
)
)
OR
(
file.path : "/etc/systemd/system/xapt.service"
AND event.action : (
"creation" OR
"file_create" OR
"rename"
)
)
AND
(
destination.port : 22
AND process.name : (
"ssh" OR
"ssh.exe" OR
"scp" OR
"plink" OR
"bash" OR
"sh"
)
AND user.name : (
"svc_*" OR
"service*"
)
)
AND
(
process.command_line : (
"*id 2>&1*" OR
"*base64*" OR
"*base64 -d*"
)
)

---

# Network Detection Query (Elastic KQL)

```kql
url.domain : "sheets.googleapis.com"
AND (
url.path : "*batchClear*" OR
url.path : "*batchUpdate*" OR
url.query : "*valueRenderOption=FORMULA*"
)
AND NOT process.name : (
"chrome" OR
"firefox" OR
"safari" OR
"msedge"
)

---
