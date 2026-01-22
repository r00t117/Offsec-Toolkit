# Offsec Toolkit

My personal collection of scripts, binaries, and tools for CTFs, OSCP, and engagements. Keeping everything centrally located so I don't have to hunt for the same binaries on every new machine.

> **Disclaimer:** These tools are for authorized testing and educational purposes only.

## 📂 Repository Structure

### 🪟 Windows & Active Directory
Tools for domain enumeration, lateral movement, and AD exploitation.
* **Enumeration:** `SharpHound.exe`, `windapsearch`, `PowerView.ps1`, `Get-SPN.ps1`
* **Attacks:** `bloodyAD`, `Certipy`, `Kerbrute`, `SharpGPOAbuse`, `Rubeus` (implied in AD folder), `targetedKerberoast`
* **Lateral Movement:** `wmiexec-pro.py`, `dcomexec.py`, `Invoke-RunasCs.ps1`, `ntlm_theft`

### ⬆️ Windows PrivEsc
Binaries to escalate from user to SYSTEM.
* **Enumeration:** `winPEASx64.exe`, `Seatbelt.exe`, `PrivescCheck.ps1`, `Sherlock.ps1`
* **Exploits:** `GodPotato-NET4.exe`, `JuicyPotato.exe`, `PrintSpoofer64.exe`, `Sigma.exe`, `SweetPotato`
* **Credential Dumping:** `mimikatz`, `LaZagne.exe`

### 🐧 Linux PrivEsc & Enumeration
Scripts to find misconfigurations on Linux boxes.
* **Enumeration:** `linpeas.sh`, `lse.sh` (Linux Smart Enumeration), `unix-privesc-check`, `Linux_EnumPE.sh`
* **Process Monitoring:** `pspy64` (snooping on cronjobs/processes)

### 🐚 Shells & Connectivity
Tools for catching shells, tunneling, and port forwarding.
* **Listeners/Handlers:** `penelope.py`, `nc64.exe` (Netcat)
* **Payloads:** `powercat.ps1`, `mk-ps-base64-encoded-revshell.py`, `create-revshell-ods-file.py`
* **Tunneling:** `SSH-Tunneling` scripts

### 🌐 Web & Network Recon
* `git-dumper`: Extracting source code from exposed .git folders
* `smtp-enum.py`: User enumeration via SMTP
* `redis-rogue-server`: Exploit for unauthorized Redis access

### 🛠️ Misc / Helpers
* `usernamer` & `UsernameGenerator.py`: Wordlist generation
* `keepass4brute.sh`: Helper for cracking KeePass files
* `mdxfind`: Google dorking/search tool

---

### 📥 Quick Download
To grab the whole toolkit zip (if you don't want to clone):
Check the [Releases](https://github.com/r00t117/Offsec-Toolkit/releases) page for `tools.zip`.
