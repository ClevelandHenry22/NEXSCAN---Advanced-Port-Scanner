# GitHub Setup Guide — NEXSCAN

This guide covers how to clone this repository, get the scanner running on Kali Linux, and how the project was pushed to GitHub from a live Kali environment.

---

## Cloning the Repository
```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
```

---

## Requirements

- Kali Linux (or any Linux distro)
- Python 3.10 or higher
- No external libraries needed — pure standard library

Check your Python version:
```bash
python3 --version
```

---

## Running the Scanner

Make the script executable first:
```bash
chmod +x port_scanner.py
```

Then run it:
```bash
# Quick scan — top 20 ports
python3 port_scanner.py -t 192.168.56.5

# Top 100 ports with banner grabbing
python3 port_scanner.py -t 192.168.56.5 --group top-100 --banners

# Scan ports 1-1024 and save results
python3 port_scanner.py -t 192.168.56.5 -p 1-1024 --output results.json
```

---

## How This Project Was Pushed to GitHub from Kali

### Step 1 — Configure Git on Kali
```bash
git config --global user.name "Your Name"
git config --global user.email "your@email.com"
```

### Step 2 — Initialize the local repo
```bash
cd ~/nexscan
git init
```

### Step 3 — Connect to GitHub
```bash
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
```

### Step 4 — Pull existing files from GitHub first

This is important if you already have files on GitHub (README, LICENSE, etc).
Skipping this step causes merge conflicts.
```bash
git pull origin main --allow-unrelated-histories
```

### Step 5 — Add, commit, and push
```bash
git add .
git commit -m "Add NEXSCAN port scanner script and setup guide"
git push origin main
```

### Step 6 — Authenticate

GitHub no longer accepts your account password for pushes. You need a Personal Access Token (PAT).

To generate one:
1. Go to GitHub → Settings → Developer Settings
2. Personal Access Tokens → Tokens (classic)
3. Click Generate new token
4. Give it a name, set expiry, and tick the repo scope
5. Copy the token — you only see it once

When Git asks for your password during push, paste the token instead.

Optionally, save your credentials so you do not have to paste it every time:
```bash
git config --global credential.helper store
```
Then push once — Git will remember it after that.

---

## Repo Structure
```
NEXSCAN-Port-Scanner/
├── port_scanner.py      # Main scanner script
├── README.md            # Project overview and usage
├── REPORT.md            # Full lab report with real scan results
├── GITHUB_SETUP.md      # This file
└── LICENSE              # License file
```

---

## Lab Setup (Kali + Metasploitable2)

If you want to replicate the scan results in this project:

1. Run Kali Linux as your attacker VM
2. Run Metasploitable2 as your target VM
3. Set both to Host-Only network in VirtualBox or VMware
4. Find Metasploitable2's IP with ifconfig (login: msfadmin / msfadmin)
5. Run the scanner pointing at that IP

Metasploitable2 is intentionally vulnerable — it is built for this kind of lab work and is completely legal to scan.

---

*NEXSCAN Project — Kali Linux | March 2026*
