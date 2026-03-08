# NEXSCAN - Advanced Port Scanner

**Built for Kali Linux | Tested against Metasploitable2

### What is NEXSCAN? 

**NEXSCAN** is a multi-threaded TCP port scanner written in pure Python. No external libraries, no root access needed - *just Python 3.10+ and a target your'e allowed to sacn.*

*It is built specifically for lab environments. If you're running Kali Linux against Metasploitable2 (or any other intentionally vulnerable VM), this tool will do exactly what you need - fast, clean output, banner grabbing, and exportable results.

---

## Lab Setup (Kali + Metasploitable2)

- *Run Kali as your attacker machine*
- *Metasploitable2 as the target*
- *Both the VMs should be on the same network (Host-Only or NAT Network both work fine in virtual box)

---

## Workflow

1. **Find Metasploitable2's IP address**
   
   *Boot into Metasploitable2, log in with `msfadmin / msfadmin`, then run*:

   `ifconfig` - *note down the IP*

2. **Set up NEXSCAN on Kali**

   `mkdir ~/nexscan` - *create directory of nexscan*

   `cd ~/nexscan` - *move to the directory*

   `nano port_scanner.py` - *paste the full script in, then* `Ctrl+O` --> *Enter to save*, `Ctrl+X` *to exit*

   `chmod +x port_scanner.py` - *make it executable*
   
3. **Run your first scan**

   `python3 port_scanner.py -t 192.168.56.5 --group top-100 --banners`

   `python3 port_scanner.py` --> *runs the script*

   `-t 192.168.56.101` --> *sets Metasploitable2 as the target*

   `--group top-100` --> *scans the 100 most common ports instead of all 65,535*

   `--banners` --> *grabs the service banners so you can see what's actually running on each open port (version info, service name)*
   



