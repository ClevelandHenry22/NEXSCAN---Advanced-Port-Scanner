# NEXSCAN - Advanced Port Scanner

**Built for Kali Linux | Tested against Metasploitable2**

### What is NEXSCAN? 

**NEXSCAN** is a multi-threaded TCP port scanner written in pure Python. No external libraries, no root access needed - *just Python 3.10+ and a target your'e allowed to sacn.*

*It is built specifically for lab environments. If you're running Kali Linux against Metasploitable2 (or any other intentionally vulnerable VM), this tool will do exactly what you need - fast, clean output, banner grabbing, and exportable results.

---

## Lab Setup (Kali + Metasploitable2)

- *Run Kali as your attacker machine*
- *Metasploitable2 as the target*
- *Both the VMs should be on the same network (Host-Only or NAT Network both work fine in virtual box)*

---

## Workflow

1. **Find Metasploitable2's IP address**
   
   *Boot into Metasploitable2, log in with `msfadmin / msfadmin`, then run*:

   `ifconfig` - *note down the IP*

   ![m2 IP](/screenshots/ifcnfg.png)

3. **Set up NEXSCAN on Kali**

   `mkdir ~/nexscan` - *create directory of nexscan*

   `cd ~/nexscan` - *move to the directory*

   `nano port_scanner.py` - *paste the full script in, then* `Ctrl+O` --> *Enter to save*, `Ctrl+X` *to exit*

   `chmod +x port_scanner.py` - *make it executable*

   ![setup](/screenshots/nx1.png)
   
5. **Run your first scan**

   `python3 port_scanner.py -t 192.168.56.5 --group top-100 --banners`

   `python3 port_scanner.py` --> *runs the script*

   `-t 192.168.56.101` --> *sets Metasploitable2 as the target*

   `--group top-100` --> *scans the 100 most common ports instead of all 65,535*

   `--banners` --> *grabs the service banners so you can see what's actually running on each open port (version info, service name)*

   ![nx output](/screenshots/nx2.png)

   ![nx output2](/screenshots/nx3.png)
   
7. **Save the results**

   `python3 port_scanner.py -t 192.168.56.5 -p 1-1024 --output results.json`

   `-p 1-1024` --> *scans ports 1 throught 1024, these are known as well known ports and cover pretty much all important services (HTTP, SSH, FTP)

   `--output results.json` --> *instead of just printing the terminal, it saves everything it found into a file called `results.json`

   ![saved output](/screenshots/out1.png)

   ![saved output2](/screenshots/out2.png)

   ![saved output3](/screenshots/new-out3.png)

---

## All Options

```
-t, --target      Target IP or hostname                  [required]
-p, --ports       Range: 1-1024  or list: 22,80,443
    --group       Predefined port group                  [default: top-20]
    --threads     Concurrent threads                     [default: 100]
    --timeout     Seconds to wait per port               [default: 1.0]
    --banners     Grab service banners (fingerprinting)
-v, --verbose     Show closed and filtered ports too
    --output      Output filename  (e.g. scan.json)
    --format      json | csv | txt                       [default: json]
```

---

## Port Groups

| Group    | What it covers                                              |
|----------|-------------------------------------------------------------|
| top-20   | The 20 most scanned ports - a good starting point           |
| top-100  | Ports 1 through 100                                         |
| web      | 80, 443, 8080, 8888, 9000, 9200 and others                  |
| database | MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle             |
| remote   | SSH, RDP, VNC, Telnet, WinRM                                 |
| mail     | SMTP, POP3, IMAP and their TLS variants                     |
| all      | All 65,535 ports — use with `--threads 300+` and a lower timeout |
---

## What to expect on Metasploitable2

*Metasploitable2 is packed with deliberately vulnerable and misconfigured services.*

*A typical scan will turn up ports like:*

- 21 - FTP(vsftpd2.3.4 - backdoored version)
- 22 - SSH
- 23 - Telnet (open and unauthenticated)
- 80 - HTTP (DVWA,phpMyAdmin)
- 139/445 - Samba (SMB shares)
- 3306 - MySQL(often no root password)
- 5432 - Postgre SQL
- 5900 - VNC
- 6667 -IRC (UnreallRCd - also backdoored)
- and many others

*Run with `--banners` to grab the version strings*

---

## How it Works

1. **Resolve the target** --> *DNS lookup*, IP validation, public/private check*
2. **Build port list** --> *From `-p` range, `--group`, or manual list*
3. **Thread pool** --> *ThreadPoolExecutor dispatches scans concurrently*
4. **TCP connect scan** --> *socket.connect_ex() - full 3-way handshake
5. **Banner grab** --> *Optional - sends HTTP HEAD or newline, reads response*
6. **Clarify result** --> *open/ closed / filtered*
7. **Live display** --> *color-coded table + real-time progress bar*
8. **Summary + export** --> *stats, danger flags, optional file output*

*The technique used in **TCP Connect Scan** - completes the full handshake, no elevated privileges needed, works reliably in most network configs. Not stealthy(connections show up in logs), this will not matter for this lab.*

---

## Lessons Learnt

- How TCP connections actually work - 3-way handshake, what open/closed/filtered means at network level.
- What ports are, why they exist, and why certain ones are more important than others
- How to work with the `socket` module to make real network connections in code
- How `ThreadPoolExecutor` works and why multi-threading makes a scanner dramatically faster
- How to build a proper CLI tool using `argparse` — the same way real tools are buil
- What reconnaissance is and why port scanning is always the first step in any assessment
- Why certain ports like Telnet, SMB, and Redis are considered dangerous when found open
- What banner grabbing is and how attackers use version info to find known vulnerabilities
- The difference between a port being closed vs filtered — and what a firewall looks like from a scanner's perspective
- Why knowing what's running on your own network matters just as much from a defensive side

---

## Legal Disclaimer

Only use this on the systems you own or have the explicit permissions to test. Unauthorized port scanning is illegal.

---

## Author

**Cleveland Henry Lore**

*Cybersecurity Enthusiast*

---

## References

- [IANA Service Name and Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) — official registry of all port numbers and their assigned services
- [Nmap: The Art of Port Scanning](https://nmap.org/book/man-port-scanning-techniques.html) — industry-standard reference for port scanning techniques and methodology
- [RFC 793 – Transmission Control Protocol (TCP)](https://www.rfc-editor.org/rfc/rfc793) — the foundational RFC that defines how TCP connections (and thus port scanning) work

---




