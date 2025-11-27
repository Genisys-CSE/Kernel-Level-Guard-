🛡️ K-Guard: Kernel-Level Linux Defense System
A Host-Based Intrusion Prevention System (HIPS) running entirely in Ring-0 (Kernel Space).

📖 Overview
K-Guard is a custom security suite designed to harden Linux systems from the inside out. Unlike traditional antivirus or firewalls (iptables, UFW) that operate in User Space, K-Guard operates as a set of Loadable Kernel Modules (LKM).

By hooking directly into the kernel's network stack (Netfilter) and system call handlers (Kprobes), K-Guard intercepts and neutralizes threats—such as DoS floods, Stealth Scans, ARP Spoofing, and Ransomware—before they can damage the operating system.

📂 Project Structure
The project is organized into three defensive layers and a central command interface:

Plaintext

K-Guard/
│
├── 📁 network/           # Module 1: Network Firewall
│   ├── level_1.c         # Source Code (Netfilter Hook)
│   └── Makefile          # Build Configuration
│
├── 📁 network2/          # Module 2: LAN/MITM Guard
│   ├── level_2.c         # Source Code (ARP Hook)
│   └── Makefile          # Build Configuration
│
├── 📁 sys_defence/       # Module 3: System & File Integrity
│   ├── file_def.c        # Source Code (Kprobes - File/Exec)
│   └── Makefile          # Build Configuration
│
└── 📜 cli_interface.sh   # The "Commander" Bash Dashboard
🚀 Key Features
1. Network Guard (/network)
Technology: Netfilter Hooks (NF_INET_PRE_ROUTING).

Anti-Scan: Detects and drops stealth scans (XMAS, NULL, Illegal Flags) by analyzing TCP headers via bitwise operations.

Anti-DoS: Implements a stateful Rate Limiter using Kernel Linked Lists and Spinlocks. Automatically blocks IPs exceeding 5 packets/sec.

2. LAN Guard (/network2)
Technology: Netfilter ARP Hooks (NF_ARP_IN).

Anti-Spoofing: Mathematically validates gateway identity by inspecting ARP headers.

Anti-MITM: Drops packets where the Source IP matches the Gateway but the MAC address does not, preventing Man-in-the-Middle attacks.

3. System Guard (/sys_defence)
Technology: Kernel Probes (Kprobes).

Integrity Shield: Prevents persistence by intercepting open() calls. Critical files (e.g., /etc/shadow) are dynamically downgraded to READ-ONLY in memory, protecting them from modification even by Root.

No-Exec Guard: Prevents malware droppers by blocking execve() calls originating from temporary directories like /tmp, /var/tmp, and /dev/shm.

🛠️ Installation & Usage
Prerequisites
A Linux System (Tested on Kali Linux / Kernel 6.x)

Kernel Headers installed:

Bash

sudo apt install linux-headers-$(uname -r) build-essential
Running K-Guard
You don't need to compile modules manually. The Commander Interface handles everything.

Clone the Repository:

Bash

git clone https://github.com/Genisys-CSE/K-Guard.git
cd K-Guard
Make the Script Executable:

Bash

chmod +x cli_interface.sh
Run the Commander (Root Required):

Bash

sudo ./cli_interface.sh
Using the Dashboard:

Select [1] to Load Network & MITM defenses.

Select [3] to Load System/Virus defenses.

Select [5] to view live security alerts (Blocked packets/processes).

🧪 Example Use Cases
Here is how K-Guard performs in real-world attack scenarios.

Scenario A: Stopping a Stealth Scan
Attacker: Tries to map the network using Nmap stealth flags to bypass standard firewalls.

Command: nmap -sX -p 80 <Target_IP>

K-Guard Response: The Netfilter hook detects the illegal flag combination (FIN+URG+PSH). The packet is silently dropped.

Result: Port appears filtered. Logs show: [K-GUARD] BLOCKED: XMAS Scan.

Scenario B: Blocking a Denial of Service (DoS)
Attacker: Floods the server with SYN packets to exhaust resources.

Command: hping3 -S --flood -p 80 <Target_IP>

K-Guard Response: The Rate Limiter detects traffic exceeding 5 packets/sec from a single IP. It switches to DROP mode immediately.

Result: Server remains responsive. Logs show: [K-GUARD] DoS BLOCKED: High Traffic.

Scenario C: Preventing Ransomware Persistence
Attacker: Gains shell access and tries to add a backdoor user to the system password file.

Command: sudo echo "hacker:x:0:0::/root:/bin/bash" >> /etc/shadow

K-Guard Response: The Kprobe intercepts the open() syscall. It detects the target is /etc/shadow and the mode is WRITE. It dynamically downgrades the file handle to READ-ONLY.

Result: Operation fails with Bad file descriptor. The file remains untouched.

Scenario D: Blocking Malware Execution
Attacker: Downloads a malicious script to /tmp and tries to run it.

Command: /tmp/exploit.sh

K-Guard Response: The execve hook detects the binary path starts with /tmp. It sends a SIGKILL signal to the process.

Result: Process is killed instantly. Logs show: [K-GUARD] NO-EXEC: Blocked execution from Dangerous Zone.

🧠 Technical Highlights
Ring-0 Execution: All logic runs in Kernel Mode for maximum performance.

Concurrency Control: Uses spin_lock to handle high-speed network traffic safely.

Memory Management: Manual handling of kmalloc and kfree within the kernel heap.

Smart Logging: Implements rate-limited logging to prevent log-flooding attacks.

⚠️ Disclaimer
This tool is intended for Educational and Defensive purposes only. It interacts with the kernel at a low level; unauthorized modification or use on production systems without understanding the code may cause system instability (Kernel Panics).

📄 License
This project is licensed under the GPL-3.0 License.

Developed by Genisys
