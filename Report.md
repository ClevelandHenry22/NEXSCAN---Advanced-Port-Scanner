# NEXSCAN — Basic Port Scanner Project Report

**Project Title:** Basic Port Scanner Script  
**Tool Name:** NEXSCAN v1.0  
**Environment:** Kali Linux → Metasploitable2  
**Language:** Python 3  
**Date:** March 2026  

---

## 1. Introduction

Port scanning is one of the most fundamental techniques in network security. Before any vulnerability assessment, penetration test, or security audit can begin, the first step is always the same — find out what's running on the target. That process starts with port scanning.

This project involved building a custom port scanner from scratch using Python, then deploying it in a controlled lab environment against Metasploitable2, a deliberately vulnerable virtual machine designed specifically for security testing and practice.

The goal was not just to scan ports, but to understand what is happening at the network level when we do — what a TCP connection attempt looks like, what open vs closed vs filtered means, and what information we can extract from a service once we know it's listening.

---

## 2. Lab Environment

The lab was set up using two virtual machines running on the same isolated network — no internet exposure, no risk of scanning anything outside the lab.

| Machine | Role | OS | IP Address |
|---|---|---|---|
| Attacker | Running NEXSCAN | Kali Linux | 192.168.56.6 |
| Target | Being scanned | Metasploitable2 | 192.168.56.5 |

**Why Metasploitable2?**

Metasploitable2 is maintained by Rapid7 and is purpose-built for exactly this kind of lab work. It runs an intentionally outdated and misconfigured Linux system loaded with vulnerable services — old versions of FTP, SSH, HTTP, Samba, MySQL, PostgreSQL, VNC, and more. It gives a realistic picture of what a poorly secured machine actually looks like from a scanner's perspective, without any legal or ethical concerns since it exists solely to be tested against.

**Network Configuration:**

Both VMs were placed on a Host-Only network in VirtualBox, meaning they could communicate with each other but neither had access to the internet or the host machine's real network. This is the safest and most practical setup for this kind of lab.

---

## 3. Tool Overview — NEXSCAN

NEXSCAN was written entirely in Python using only the standard library — no external packages, no pip installs. It can be dropped onto any system with Python 3.10+ and run immediately.

### Key Features

**Multi-threaded scanning** — Uses Python's `ThreadPoolExecutor` to scan many ports at the same time. Instead of checking ports one by one (which would take hours on a full scan), it fires off dozens or hundreds of connection attempts in parallel. As seen in the actual scan results, 1,024 ports were scanned in just 2.13 seconds with 100 threads.

**Service identification** — Includes a built-in database of 60+ well-known port-to-service mappings. When a port comes back open, the tool immediately tells you what's likely running on it — not just the port number.

**Banner grabbing** — Once an open port is confirmed, the tool optionally connects again and sends a small probe to get the service banner — the text a server sends back when you first connect. Banners often contain the software name and version number, which is exactly the kind of information used in vulnerability research.

**Danger flagging** — Certain ports are automatically flagged as dangerous when found open. These include Telnet (port 23, sends all data unencrypted), SMB (ports 139/445, historically a major ransomware vector), Redis (port 6379, frequently left without authentication), and the Metasploit default listener (port 4444).

**Export options** — Results can be saved to JSON, CSV, or plain text for documentation or further analysis.

**Live progress bar** — Displays real-time scan progress including percentage complete, estimated time remaining, and current scan rate in ports per second.

### Scan Technique — TCP Connect Scan

NEXSCAN uses what is known as a TCP Connect Scan. For each port, it attempts to complete a full TCP three-way handshake:
```
Scanner → SYN       → Target
Scanner ← SYN/ACK   ← Target   (port is OPEN)
Scanner → ACK       → Target
Scanner → RST       → Target   (we close it immediately)
```

If the target responds with RST/ACK instead of SYN/ACK, the port is **closed** — something actively refused the connection. If there is no response at all within the timeout window, the port is marked **filtered** — likely a firewall is silently dropping the packets.

This technique requires no special privileges (no root or sudo needed) and works reliably across all operating systems and network configurations.

---

## 4. Methodology

### Step 1 — Setup
```bash
# Create a working directory on Kali
mkdir ~/nexscan && cd ~/nexscan

# Create the script using nano
nano port_scanner.py
# (paste the full script, then Ctrl+O to save, Ctrl+X to exit)

# Make it executable
chmod +x port_scanner.py
```

### Step 2 — Verify Connectivity

Before scanning, confirm Kali can reach Metasploitable2:
```bash
ping 192.168.56.5
```

A successful ping confirms the machines can communicate and the scan will reach the target.

### Step 3 — Initial Reconnaissance Scan with Banner Grabbing

Start with the top 100 common ports and enable banner grabbing to get version information right away:
```bash
python3 port_scanner.py -t 192.168.56.5 --group top-100 --banners
```

### Step 4 — Broader Scan Across Well-Known Ports

Expand to the full 1,024 well-known ports and save everything to a file:
```bash
python3 port_scanner.py -t 192.168.56.5 -p 1-1024 --output results.json
```

### Step 5 — Targeted Group Scans

Run focused scans on specific service categories:
```bash
# Database services
python3 port_scanner.py -t 192.168.56.5 --group database

# Remote access services
python3 port_scanner.py -t 192.168.56.5 --group remote

# Web services
python3 port_scanner.py -t 192.168.56.5 --group web
```

---

## 5. Results

Two scans were run against Metasploitable2 at `192.168.56.5`.

---

### Scan 1 — Top 100 Ports with Banner Grabbing

**Command:**
```bash
python3 port_scanner.py -t 192.168.56.5 --group top-100 --banners
```

**Scan Stats:** 100 ports | 3.32 seconds | 100 threads

| Port | Service | Banner Captured | Risk |
|---|---|---|---|
| 21/tcp | FTP | `220 (vsFTPd 2.3.4)` | HIGH — backdoored version |
| 22/tcp | SSH | `SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1` | MEDIUM — outdated version |
| 23/tcp | Telnet | garbled (expected — binary protocol) | HIGH — unencrypted, DANGER flagged |
| 25/tcp | SMTP | `220 metasploitable.localdomain ESMTP Postfix (Ubuntu)` | MEDIUM |
| 53/tcp | DNS | — | MEDIUM |
| 80/tcp | HTTP | `HTTP/1.1 200 OK` | MEDIUM |

**Summary:** 6 open ports | 0 filtered | 94 closed  
**Dangerous ports auto-flagged:** Port 23 (Telnet)

---

### Scan 2 — Ports 1–1024 Full Sweep

**Command:**
```bash
python3 port_scanner.py -t 192.168.56.5 -p 1-1024 --output results.json
```

**Scan Stats:** 1,024 ports | 2.13 seconds | 100 threads | results saved to `results.json`

| Port | Service | Risk |
|---|---|---|
| 21/tcp | FTP | HIGH — vsftpd 2.3.4 backdoor |
| 22/tcp | SSH | MEDIUM — outdated OpenSSH |
| 23/tcp | Telnet | HIGH — unencrypted, DANGER flagged |
| 25/tcp | SMTP | MEDIUM |
| 53/tcp | DNS | MEDIUM |
| 80/tcp | HTTP | MEDIUM |
| 111/tcp | RPC | MEDIUM |
| 139/tcp | NetBIOS-SSN | HIGH — SMB attack surface, DANGER flagged |
| 445/tcp | SMB | HIGH — multiple known exploits, DANGER flagged |
| 512/tcp | rexec | HIGH — unauthenticated remote exec |
| 513/tcp | rlogin | HIGH — unauthenticated remote login |
| 514/tcp | Syslog/rsh | HIGH — unauthenticated remote shell |

**Summary:** 12 open ports | 0 filtered | 1,012 closed  
**Dangerous ports auto-flagged:** Port 445 (SMB), Port 23 (Telnet), Port 139 (NetBIOS-SSN)

---

## 6. Analysis

### What the Results Tell Us

The scan results paint a clear picture of a machine that was never hardened — which is exactly the point of Metasploitable2. Several findings stand out:

**vsftpd 2.3.4 on port 21** — The banner grab caught this version number immediately: `220 (vsFTPd 2.3.4)`. This is one of the most well-known examples of a supply-chain backdoor in open source software. This specific version was compromised before release. Connecting to it and sending a smiley face (`:)`) in the username field triggers a root shell on port 6200. Without banner grabbing we would only know FTP is open — with it, we have a confirmed critical vulnerability in under 4 seconds.

**OpenSSH 4.7p1 on port 22** — The full banner `SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1` tells us exactly what version is running. OpenSSH 4.7 is from 2007 and has multiple documented vulnerabilities. In a real assessment this version string goes straight into CVE lookup.

**Telnet on port 23** — NEXSCAN flagged this as DANGER automatically. Any credentials sent over this connection travel across the network in plain text — usernames, passwords, everything. Anyone with access to the network traffic can read it without any decryption needed. In any real environment, an open Telnet port is an instant critical finding.

**SMB on ports 139 and 445** — Both flagged as DANGER. Outdated Samba running on these ports exposes the machine to a class of attacks that have caused some of the most damaging breaches in history. The WannaCry ransomware attack of 2017 spread almost entirely through exposed SMB ports running outdated software.

**r-services on ports 512, 513, 514** — rexec, rlogin, and rsh are legacy Unix remote access services from an era before modern authentication. They are notoriously insecure and in many configurations allow access with no password at all. Finding all three open on the same machine is a significant finding.

**SMTP banner on port 25** — `220 metasploitable.localdomain ESMTP Postfix (Ubuntu)` confirms this is a Postfix mail server and leaks the internal hostname `metasploitable.localdomain`. Hostname disclosure is a small thing on its own but contributes to the overall picture of the target.

### The Value of Banner Grabbing

The difference between Scan 1 (with banners) and Scan 2 (without) shows clearly why banner grabbing matters. In Scan 1, port 21 doesn't just show as FTP open — it shows `220 (vsFTPd 2.3.4)`, a known backdoored version that can be exploited immediately. Without that version string, it's just an open port. With it, it's a confirmed attack path. The difference between "port 21 is open" and "vsftpd 2.3.4 is running on port 21" is the difference between a lead and a confirmed vulnerability.

### Scan Speed

Both scans completed extremely fast — 3.32 seconds for 100 ports and 2.13 seconds for 1,024 ports. This is a direct result of the multi-threaded design. With 100 threads running in parallel, the scanner doesn't wait for one port to respond before moving to the next. It fires all 100 connection attempts simultaneously and collects results as they come back.

---

## 7. Key Concepts Demonstrated

**TCP/IP and the Three-Way Handshake** — Every open port discovery in this project is the result of a successful SYN/SYN-ACK/ACK exchange. Understanding this process is foundational to understanding how networks communicate.

**Concurrency in Security Tools** — Real tools don't scan ports one at a time. The multi-threaded approach used here mirrors how professional tools like Nmap operate — dispatching many simultaneous connection attempts and collecting results as they come back. 1,024 ports in 2.13 seconds is the direct result of this.

**Reconnaissance as a Phase** — Port scanning sits within the reconnaissance phase of any security assessment. The information gathered here — open ports, service versions, potential attack surfaces — directly feeds into what comes next, whether that's further enumeration or exploitation.

**Defense Through Visibility** — Everything that NEXSCAN found on Metasploitable2 from an attacker's perspective is also what a defender needs to know about their own network. Running a scan like this on your own systems tells you exactly what an outsider sees.

**Documentation and Reporting** — The `--output results.json` flag in Scan 2 saved all findings to a file automatically. Findings without documentation don't exist. Every scan should produce a record.

---

## 8. Lessons Learned

This project covers more ground than it might appear to at first. On the technical side, it involves real network programming — opening sockets, handling timeouts, reading raw bytes off a connection. On the security side, it demonstrates the actual first steps of a real assessment. On the development side, it shows how to structure a proper CLI tool with argument parsing, modular functions, threaded execution, and file output.

Working against Metasploitable2 specifically makes the results meaningful rather than abstract. Every open port on that machine has a story — a backdoor, a misconfiguration, a default credential that was never changed. The vsftpd 2.3.4 banner that appeared in Scan 1 is a real, exploitable vulnerability. The Telnet port that got flagged DANGER is genuinely dangerous. Seeing those appear in the scan output and understanding why they matter is where the real learning is.

---

## 9. Ethical and Legal Notice

All scanning in this project was performed exclusively within an isolated lab environment against Metasploitable2, a machine that exists for this exact purpose. No external systems, public IPs, or networks outside the lab were targeted at any point.

Port scanning unauthorized systems is illegal in most jurisdictions regardless of intent. The techniques demonstrated here should only ever be used on systems you own outright or have explicit written permission to test.

---

## 10. Tools and References

| Item | Details |
|---|---|
| Scanner | NEXSCAN v1.0 (custom — this project) |
| Attacker OS | Kali Linux |
| Target | Metasploitable2 by Rapid7 — `192.168.56.5` |
| Language | Python 3.10+ |
| Libraries used | `socket`, `threading`, `argparse`, `concurrent.futures`, `json`, `csv` |
| CVE Database | https://cve.mitre.org |
| Exploit Reference | https://www.exploit-db.com |
| Metasploitable2 | https://docs.rapid7.com/metasploit/metasploitable-2 |

---

*NEXSCAN Project — Lab Report | Kali Linux Environment | March 2026*
