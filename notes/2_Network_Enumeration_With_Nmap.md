## Table of Contents
- [A. Introduction to Nmap](#a-introduction-to-nmap)
- [B. Host Discovery](#b-host-discovery)
- [C. Host and Port Scanning](#c-host-and-port-scanning)
- [D. Nmap Scripting Engine](#d-nmap-scripting-engine)
- [E. Performance](#e-performance)
- [F. Firewall and IDS/IPS Evasion](#f-firewall-and-idsips-evasion)
- [G. Firewall and IDS/IPS Evasion Labs](#g-firewall-and-idsips-evasion-labs)
  - [Easy Lab](#easy-lab)
  - [Medium Lab](#medium-lab)
  - [Hard Lab](#hard-lab)

---

# A. Introduction to Nmap
## Syntax
```bash
nmap <scan types> <options> <target>
```

## Scan Techniques
- `-sS/sT/sA/sW/sM`: TCP SYN/Connect()/ACK/Window/Maimon scans
- `-sU`: UDP Scan
- `-sN/sF/sX`: TCP Null, FIN, and Xmas scans
- `--scanflags <flags>`: Customize TCP scan flags
- `-sI <zombie host[:probeport]>`: Idle scan
-  `-sY/sZ`: SCTP INIT/COOKIE-ECHO scans
-  `-sO`: IP protocol scan
-  `-b <FTP relay host>`: FTP bounce scan

TCP-SYN scan (`-sS`) is one of the default settings, which sends one packet with the SYN flag and therefore, never completes the 3-way handshake.
- If our target sends a `SYN-ACK` flagged packet back to us, Nmap detects that the port is `open`.
- If the target responds with an `RST` flagged packet, it is an indicator that the port is `closed`.
- If Nmap does not receive a packet back, it will display it as `filtered`. Depending on the firewall configuration, certain packets may be dropped or ignored by the firewall.

---

# B. Host Discovery
## Scan Network Range
```bash
nmap 10.129.2.0/24 -sn -oA tnet

# 10.129.2.0/24: Target network range.
# -sn: Disables port scanning.
# -oA tnet: Stores the results in all formats starting with the name 'tnet'.
```

## Scan IP List
```bash
nmap -sn -oA tnet -iL hosts.lst
# -iL: Performs defined scans against targets in provided 'hosts.lst' list.
```

## Scan Multiple IPs
```bash
nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20
```

```bash
nmap -sn -oA tnet 10.129.2.18-20
# If these IP addresses are next to each other, we can also define the range in the respective octet.
```

## Scan Single IP
```bash
nmap 10.129.2.18 -sn -oA host 
```

## ICMP Echo Requests VS ARP Pings
- If we disable port scan (`-sn`), Nmap automatically ping scan with ICMP Echo Requests (`-PE`). 
- Once such a request is sent, we usually expect an ICMP reply if the pinging host is alive. The more interesting fact is that our previous scans did not do that because before Nmap could send an ICMP echo request, it would send an ARP ping resulting in an ARP reply. We can confirm this with the "`--packet-trace`" option. To ensure that ICMP echo requests are sent, we also define the option (`-PE`) for this.

```bash
selwynang@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:08 CEST
SENT (0.0074s) ARP who-has 10.129.2.18 tell 10.10.14.2
RCVD (0.0309s) ARP reply 10.129.2.18 is-at DE:AD:00:00:BE:EF
Nmap scan report for 10.129.2.18
Host is up (0.023s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
```

- To disable ARP requests and scan our target with the desired ICMP echo requests, we can disable ARP pings by including `--disable-arp-ping`.

```bash
selwynang@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:12 CEST
SENT (0.0107s) ICMP [10.10.14.2 > 10.129.2.18 Echo request (type=8/code=0) id=13607 seq=0] IP [ttl=255 id=23541 iplen=28 ]
RCVD (0.0152s) ICMP [10.129.2.18 > 10.10.14.2 Echo reply (type=0/code=0) id=13607 seq=0] IP [ttl=128 id=40622 iplen=28 ]
Nmap scan report for 10.129.2.18
Host is up (0.086s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.11 seconds
```

- TTL value of 128 suggests that the system is Windows. TTL value of 64 suggests that the system is Linux/macOS (NOTE: This is just a heuristic, not a proof).

---

# C. Host and Port Scanning
To view the scan status, we can press the `[Space Bar]` during the scan, which will cause Nmap to show us the scan status.

Another option (`--stats-every=5s`) that we can use is defining how periods of time the status should be shown. Here we can specify the number of seconds (s) or minutes (m), after which we want to get the status.

## Port States
| State | Description |
| --- | --- |
| `open` | This indicates that the connection to the scanned port has been established. These connections can be TCP connections, UDP datagrams as well as SCTP associations. |
| `closed` | When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an RST flag. This scanning method can also be used to determine if our target is alive or not. |
| `filtered` | Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target. |
| `unfiltered` | This state of a port only occurs during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed. |
| `open\|filtered` | If we do not get a response for a specific port, Nmap will set it to that state. This indicates that a firewall or packet filter may protect the port. |
| `closed\|filtered` | This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall. |

## Discovering Open TCP Ports
- `-sS`: SYN scan set only to default when we run it as root because of the socket permissions required to create raw TCP packets. It is generally considered more stealthy because they do not complete the full handshake, leaving the connection incomplete after sending the initial SYN packet. This minimizes the chance of triggering connection logs while still gathering port state information.
- `-sT`: Otherwise, TCP connect scan is performed by default. It is highly accurate because it completes the three-way TCP handshake, allowing us to determine the exact state of a port (open, closed, or filtered). However, it is not the most stealthy, as it fully establishes a connection, which creates logs on most systems and is easily detected by modern IDS/IPS solutions.
- `-p 22,80,139,445`: Defining ports individually.
- `-p 22-445`: Defining port range.
- `--top-ports=10`: Defining by top ports.
- `-p-`: Scans all ports.
- `-F`: Fast port scan, which contains 100 ports.

## Discovering Open UDP Ports
- `-sU`: UDP scan, which does not require a 3-way handshake, making the timeout longer, and hence slower than the TCP scan.

## Version Scan
- `-sV`: Used to get additional available information from the open ports. Can identify versions, service names, and details about our target.

## Saving the Results
- `-oN`: Normal output with the `.nmap` file extension
- `-oG`: Grepable output with the `.gnmap` file extension
- `-oX`: XML output with the `.xml` file extension
- `-oA`: Save the results in all formats.

To convert the stored results from XML format to HTML, we can use the tool xsltproc:
```bash
xsltproc target.xml -o target.html
```

---

# D. Nmap Scripting Engine

| Category | Description |
| --- | --- |
| `auth` | Determination of authentication credentials. |
| `broadcast` | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans. |
| `brtue` | Executes scripts that try to log in to the respective service by brute-forcing with credentials. |
| `default` | Default scripts executed by using the `-sC` option.|
| `discovery` | Evaluation of accessible services. |
| `dos` |These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services. |
| `exploit` | This category of scripts tries to exploit known vulnerabilities for the scanned port. |
| `external` | Scripts that use external services for further processing. |
| `fuzzer` | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time. |
| `intrusive` | Intrusive scripts that could negatively affect the target system. |
| `malware` | Checks if some malware infects the target system. |
| `safe` |Defensive scripts that do not perform intrusive and destructive access. |
| `version` | Extension for service detection. |
| `vuln` | Identification of specific vulnerabilities. |

## Default Scripts
```bash
sudo nmap <target> -sC
```

## Specific Scripts Category
```bash
sudo nmap <target> --script <category>
```

## Defined Scripts
```bash
sudo nmap <target> --script <script-name>,<script-name>,...
```

## Aggressive Scan
- `-A`: Scans the target with multiple options such as service detection `-sV`, OS detection `-O`, traceroute `--traceroute`, and with the default NSE scripts `-sC`.

---

# E. Performance

## Timeouts
When Nmap sends a packet, it takes some time (Round-Trip-Time) to receive a response from the scanned port. Nmap starts with a high timeout of 100 ms. However, too short a RTT may cause us to overlook hosts.
- `--min-rtt-timeout <miliseconds>`: Sets the specified time value as minimum RTT timeout.
- `--initial-rtt-timeout <miliseconds>`: Sets the specified time value as initial RTT timeout.
- `--min-rtt-timeout <miliseconds>`: Sets the specified time value as maximum RTT timeout.

## Max Retries
- `--max-retries <number>`: Default value is 10, but we can reduce it to 0. This means if Nmap does not receive a response for a port, it won't send any more packets to that port and will skip it.

## Rates
- `--min-rate <number>`: When setting the minimum rate for sending packets, we tell Nmap to simultaneously send the specified number of packets.

## Timing
`-T <0-5>`: Determines the aggressiveness of our scans. If the scan is too aggressive, security systems may block us due to the produced network traffic. Default timing template used is `-T 3`.
- `-T 0` / `-T paranoid`
- `-T 1` / `-T sneaky`
- `-T 2` / `-T polite`
- `-T 3` / `-T normal`
- `-T 4` / `-T aggressive`
- `-T 5` / `-T insane`

---

# F. Firewall and IDS/IPS Evasion

## ACK Scans
- Nmap's TCP ACK scan (`-sA`) method is much harder to filter for firewalls and IDS/IPS systems than regular SYN (`-sS`) or Connect scans (`-sT`) because they only send a TCP packet with only the ACK flag. 
- When a port is closed or open, the host must respond with an RST flag. Unlike outgoing connections, all connection attempts (with the SYN flag) from external networks are usually blocked by firewalls. 
- However, the packets with the ACK flag are often passed by the firewall because the firewall cannot determine whether the connection was first established from the external network or the internal network.

## Decoy Scans
- `-D`: With this method, Nmap generates various random IP addresses inserted into the IP header to disguise the origin of the packet sent. With this method, we can generate random (`RND`) a specific number (for example: 5) of IP addresses separated by a colon (:). Our real IP address is then randomly placed between the generated IP addresses.

```bash
selwynang@htb[/htb]$ sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 16:14 CEST
SENT (0.0378s) TCP 102.52.161.59:59289 > 10.129.2.28:80 S ttl=42 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0378s) TCP 10.10.14.2:59289 > 10.129.2.28:80 S ttl=59 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 210.120.38.29:59289 > 10.129.2.28:80 S ttl=37 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 191.6.64.171:59289 > 10.129.2.28:80 S ttl=38 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 184.178.194.209:59289 > 10.129.2.28:80 S ttl=39 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 43.21.121.33:59289 > 10.129.2.28:80 S ttl=55 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
RCVD (0.1370s) TCP 10.129.2.28:80 > 10.10.14.2:59289 SA ttl=64 id=0 iplen=44  seq=4056111701 win=64240 <mss 1460>
Nmap scan report for 10.129.2.28
Host is up (0.099s latency).

PORT   STATE SERVICE
80/tcp open  http
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
```

- `-S`: Manually specify the source IP address (`-S`) to test if we get better results with this one. Decoys can be used for SYN, ACK, ICMP scans, and OS detection scans.

```bash
selwynang@htb[/htb]$ sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-22 01:16 CEST
Nmap scan report for 10.129.2.28
Host is up (0.010s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%), Linux 2.6.32 - 3.10 (96%), Linux 3.4 - 3.10 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Synology DiskStation Manager 5.2-5644 (94%), Linux 2.6.32 - 2.6.35 (94%), Linux 2.6.32 - 3.5 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 4.11 seconds

# -n: Disables DNS resolution.
# -e tun0: Sends all requests through the specified interface.
```

## DNS Proxying
- Nmap still gives us a way to specify DNS servers ourselves (`--dns-server <ns>,<ns>`). This method could be fundamental to us if we are in a demilitarized zone (DMZ). The company's DNS servers are usually more trusted than those from the Internet. So, for example, we could use them to interact with the hosts of the internal network. 
- As another example, we can use TCP port 53 as a source port (`--source-port`) for our scans. If the administrator uses the firewall to control this port and does not filter IDS/IPS properly, our TCP packets will be trusted and passed through.
- If we have found out that the firewall accepts TCP port 53, it is very likely that IDS/IPS filters might also be configured much weaker than others. We can test this by trying to connect to this port by using `netcat`.

```bash
selwynang@htb[/htb]$ ncat -nv --source-port 53 10.129.2.28 50000

Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.129.2.28:50000.
220 ProFTPd
```

---

# G. Firewall and IDS/IPS Evasion Labs

## Easy Lab
```bash
┌─[eu-academy-5]─[10.10.15.22]─[htb-ac-2300483@htb-wk60n0hwcw]─[~]
└──╼ [★]$ sudo nmap -sS -sV -O -p22,80,1001 10.129.2.80
Starting Nmap 7.95 ( https://nmap.org ) at 2026-08-21 12:49 EDT
Nmap scan report for 10.129.2.80
Host is up (0.26s latency).

PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open     http    Apache httpd 2.4.29 ((Ubuntu))
1001/tcp filtered webpush
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.45 seconds

```

## Medium Lab
```bash
┌─[eu-academy-5]─[10.10.15.22]─[htb-ac-2300483@htb-wk60n0hwcw]─[~]
└──╼ [★]$ sudo nmap -sU -sV -p53 10.129.2.48
Starting Nmap 7.95 ( https://nmap.org ) at 2026-08-21 12:34 EDT
Nmap scan report for 10.129.2.48
Host is up (0.26s latency).

PORT   STATE SERVICE VERSION
53/udp open  domain  (unknown banner: HTB{GoTtgUnyze9Psw4vGjcuMpHRp})
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-UDP:V=7.95%I=7%D=8/21%Time=6A887DFF%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReq,57,"\0\x06\x85\0\0\x01\0\x01\0\x01\0\0\x07version\x04bind
SF:\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\x1f\x1eHTB{GoTtgUnyze9Psw4
SF:vGjcuMpHRp}\xc0\x0c\0\x02\0\x03\0\0\0\0\0\x02\xc0\x0c")%r(DNSStatusRequ
SF:est,C,"\0\0\x90\x04\0\0\0\0\0\0\0\0")%r(NBTStat,105,"\x80\xf0\x80\x90\0
SF:\x01\0\0\0\r\0\0\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\x02
SF:\0\x01\x006\xee\x80\0\x14\x01C\x0cROOT-SERVERS\x03NET\0\0\0\x02\0\x01\x
SF:006\xee\x80\0\x04\x01H\xc0\?\0\0\x02\0\x01\x006\xee\x80\0\x04\x01K\xc0\
SF:?\0\0\x02\0\x01\x006\xee\x80\0\x04\x01B\xc0\?\0\0\x02\0\x01\x006\xee\x8
SF:0\0\x04\x01L\xc0\?\0\0\x02\0\x01\x006\xee\x80\0\x04\x01M\xc0\?\0\0\x02\
SF:0\x01\x006\xee\x80\0\x04\x01D\xc0\?\0\0\x02\0\x01\x006\xee\x80\0\x04\x0
SF:1I\xc0\?\0\0\x02\0\x01\x006\xee\x80\0\x04\x01G\xc0\?\0\0\x02\0\x01\x006
SF:\xee\x80\0\x04\x01F\xc0\?\0\0\x02\0\x01\x006\xee\x80\0\x04\x01A\xc0\?\0
SF:\0\x02\0\x01\x006\xee\x80\0\x04\x01E\xc0\?\0\0\x02\0\x01\x006\xee\x80\0
SF:\x04\x01J\xc0\?");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.85 seconds
```


## Hard Lab
```bash
┌─[eu-academy-5]─[10.10.15.22]─[htb-ac-2300483@htb-wk60n0hwcw]─[~]
└──╼ [★]$ sudo ncat -nv --source-port 53 10.129.157.193 50000
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Connected to 10.129.157.193:50000.
220 HTB{kjnsdf2n982n1827eh76238s98di1w6}
```

