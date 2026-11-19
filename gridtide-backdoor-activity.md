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

## Why the endpoint logic is split into four queries

An earlier version combined everything into one KQL query. In KQL, `AND` binds tighter than `OR`, so that query evaluated as *"xapt execution **OR** (systemd file creation **AND** SSH on port 22 **AND** an `id`/`base64` command line)"*. The second half can never match, because no single event is a file creation, a network connection and a process command line at the same time.

Each behaviour below is a separate query that a single event can satisfy. To raise confidence, correlate them per host in an EQL sequence or by alert grouping on `host.id`.

---

# Endpoint Detection Queries (Elastic KQL)

## 1. xapt execution

```kql
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
```

## 2. systemd service persistence

```kql
file.path : "/etc/systemd/system/xapt.service"
AND event.action : (
  "creation" OR
  "file_create" OR
  "rename"
)
```

## 3. SSH from service accounts

```kql
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
```

## 4. Recon and encoded commands run by service accounts

```kql
process.command_line : (
  "*id 2>&1*" OR
  "*base64 -d*" OR
  "*base64*"
)
AND user.name : (
  "svc_*" OR
  "service*"
)
```

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
```

---
