# SHROUD - PoC of an anti port scanner

**Shroud** is a *proof of concept* of an **anti-SYN scan** based on *false positive* flooding.

Basically it looks for incoming tcp *SYN* packets on host's closed ports and reply with *SYN-ACK* packet to initiate a three way handshake properly.

Below an example of the results of the `nmap -sS 127.0.0.1 -p-` scan on a sample host **not running shroud**:
```
Starting Nmap 7.40 ( https://nmap.org ) at 2017-04-29 19:45 CEST
Nmap scan report for localhost.localdomain (127.0.0.1)
Host is up (0.0000040s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.76 seconds
```

And the results of the same scan **running shroud**:
```
Starting Nmap 7.40 ( https://nmap.org ) at 2017-04-29 20:37 CEST
Nmap scan report for localhost.localdomain (127.0.0.1)
Host is up (0.021s latency).
PORT      STATE SERVICE
1/tcp     open  tcpmux
2/tcp     open  compressnet
3/tcp     open  compressnet
4/tcp     open  unknown
5/tcp     open  rje
6/tcp     open  unknown
7/tcp     open  echo
8/tcp     open  unknown
9/tcp     open  discard
10/tcp    open  unknown
11/tcp    open  systat
12/tcp    open  unknown
13/tcp    open  daytime
14/tcp    open  unknown
15/tcp    open  netstat
16/tcp    open  unknown
17/tcp    open  qotd
18/tcp    open  msp
19/tcp    open  chargen
20/tcp    open  ftp-data
21/tcp    open  ftp
22/tcp    open  ssh
23/tcp    open  telnet
24/tcp    open  priv-mail
25/tcp    open  smtp
26/tcp    open  rsftp
27/tcp    open  nsw-fe
[...]
65531/tcp open  unknown
65532/tcp open  unknown
65533/tcp open  unknown
65534/tcp open  unknown
65535/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 10.88 seconds
```

# Compiling
You can compile **shroud** with:

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug -G "CodeBlocks - Unix Makefiles" <path to shroud project>
make
```

# Running
**shroud** needs *root* permission to run properly because of raw socket usage.

## Troubleshooting

### Ports appear to be closed while running shroud
It happens because you have to disable OS' *RST* responses to *SYN* packet sent to closed ports because if they are sent before the *SYN-ACK* (and they are!) the port scanner will know the ports are closed.

You could do this with a simple `iptables` rule:

`iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`
