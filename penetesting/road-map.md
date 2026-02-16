Roadmap (phased)
- Weeks 1–2
    - Set up lab; OverTheWire Bandit; THM: Introductory Networking + Linux Fundamentals.
    - Watch TCM intro videos; take notes with Obsidian.
- Weeks 3–4
    - Nmap/Wireshark fundamentals; THM: Jr Penetration Tester path modules on scanning, enumeration.
    - PortSwigger Academy: HTTP basics, Authentication, Access control.
- Weeks 5–6
    - Web vulns: XSS, SQLi, SSRF on PortSwigger; practice with Juice Shop/DVWA in your lab.
    - OS priv esc: THM Linux/Windows PrivEsc rooms; study linPEAS/winPEAS output interpretation.
- Weeks 7–8
    - Active Directory basics: THM Attacktive Directory and Breaching AD (lab only).
    - Do 2–3 HTB Starting Point boxes; write a short report for each (findings, risk, remediation).


- Phase 0 — Orientation (1–2 weeks)
    - Ethics & legality: read PTES, NIST 800-115, and understand rules of engagement and scope.
    - Setup: install a hypervisor (VirtualBox/VMware), create a Kali/Parrot VM + a Windows VM, enable snapshots, and set up a safe test network.
    - Start hands-on immediately: OverTheWire Bandit; TryHackMe “Pre-Security.”
- Phase 1 — Core Foundations (1–3 months)
    - Networking: IP/TCP/UDP, DNS, DHCP, routing, subnets; traffic analysis with Wireshark.
    - OS basics: Linux (users/permissions, services, SSH) and Windows (users/groups, services, registry, PowerShell).
    - Programming/scripting: Python, Bash, and PowerShell enough to automate tasks.
    - Web basics: HTTP, cookies/sessions, same-origin policy, common auth flows.
    - Methodology: recon → enumeration → exploitation → privilege escalation → lateral movement → reporting. Study PTES, OWASP Testing Guide.
    - Practice: TryHackMe “Jr Penetration Tester” and PortSwigger Web Security Academy.
- Phase 2 — Pentest Skills (3–6 months)
    - External/network: host discovery, service enumeration, vuln research, exploitation frameworks.
    - Web: auth issues, IDOR, XSS, SQLi/NoSQLi, SSRF, file upload/RCE, deserialization.
    - Privilege escalation: Linux/Windows privesc techniques; post-exploitation hygiene.
    - Active Directory basics: domains, Kerberos, GPOs, common misconfigs and attack paths (learn in lab environments).
    - Reporting: evidence, risk ratings, remediation, exec summaries.
    - Practice: Hack The Box “Starting Point,” THM “Offensive Pentesting,” retired HTB boxes with walkthroughs.
- Phase 3 — Specializations (6–12+ months, optional)
    - AD/red teaming labs, cloud (AWS/Azure/GCP), wireless, mobile, containers/K8s, code review.
    - Realistic environments: HTB Pro Labs, OffSec Proving Grounds, INE/Altered Security AD labs.
    - Bug bounty (web/cloud heavy) and building a portfolio (sanitized write-ups, don’t spoil active boxes).

Tools you’ll actually use

- OS & environment
    - Kali or Parrot; a stable Linux (Ubuntu) + Windows 10/11 VM; VS Code; Git; Obsidian/CherryTree for notes; draw.io or Obsidian canvas for diagrams.
- Recon & discovery
    - Nmap, Masscan; Amass/Subfinder (subdomains); theHarvester; DNS utilities; Shodan/Censys for research.
- Web testing
    - Burp Suite (Community or Pro), OWASP ZAP, ffuf/gobuster, dirsearch, nuclei, Postman.
- Exploitation & vulns
    - Metasploit, searchsploit/Exploit-DB; sqlmap (use only in labs or scoped tests).
- Credential & auth testing
    - John the Ripper, Hashcat, CeWL, wordlists (SecLists).
- Network & traffic
    - Wireshark, mitmproxy, Bettercap (lab use), Responder (lab/authorized AD testing).
- Windows/AD (lab/authorized environments only)
    - BloodHound + SharpHound, Impacket toolkit, CrackMapExec, Sysinternals. Study tools like Rubeus/Mimikatz conceptually; use only in legal labs.
- Privilege escalation/post-ex
    - linPEAS/winPEAS, pspy/ProcMon, GTFOBins, LOLBAS.
- Cloud (for cloud pentesting)
    - ScoutSuite, Prowler, Pacu, CloudSploit, CloudGoat (lab).
- Wireless/mobile (lab only)
    - Aircrack-ng suite, Kismet, WiFite; MobSF, Frida.

YouTube channels/playlists (free)

- TCM Security (Heath Adams) – intros, practical content: [https://www.youtube.com/c/TCMSecurityAcademy](https://www.youtube.com/c/TCMSecurityAcademy)
- IppSec – deep HTB walkthroughs, methodology: [https://www.youtube.com/c/ippsec](https://www.youtube.com/c/ippsec)
- John Hammond – CTFs, malware basics, tooling: [https://www.youtube.com/c/JohnHammond010](https://www.youtube.com/c/JohnHammond010)
- NahamSec – recon and bug bounty live: [https://www.youtube.com/c/NahamSec](https://www.youtube.com/c/NahamSec)
- LiveOverflow – clear explainers (web, pwn, theory): [https://www.youtube.com/c/LiveOverflow](https://www.youtube.com/c/LiveOverflow)
- PortSwigger (Burp) – labs and web security: [https://www.youtube.com/c/PortSwigger](https://www.youtube.com/c/PortSwigger)
- HackerSploit – practical offensive basics: [https://www.youtube.com/c/HackerSploit](https://www.youtube.com/c/HackerSploit)
- InsiderPhD – bug bounty methodology/reporting: [https://www.youtube.com/c/InsiderPhD](https://www.youtube.com/c/InsiderPhD)
- pwn.college – free offensive security curriculum: [https://pwn.college/](https://pwn.college/)
- TryHackMe and Hack The Box official channels for walkthroughs and tips.

Hands‑on labs and platforms

- Beginner-friendly (guided)
    - TryHackMe: Pre-Security, Jr Penetration Tester, Offensive Pentesting, Breaching AD — [https://tryhackme.com](https://tryhackme.com/)
    - PortSwigger Web Security Academy (must-do for web) — [https://portswigger.net/web-security](https://portswigger.net/web-security)
    - OverTheWire: Bandit, Narnia, etc. — [https://overthewire.org/wargames/](https://overthewire.org/wargames/)
- Challenge-based
    - Hack The Box: Starting Point → Tiered boxes; Academy modules — [https://www.hackthebox.com](https://www.hackthebox.com/)
    - picoCTF (fundamentals, CTF style) — [https://picoctf.org/](https://picoctf.org/)
    - VulnHub boxes (offline VMs) — [https://www.vulnhub.com/](https://www.vulnhub.com/)
- Realistic/professional
    - OffSec Proving Grounds — [https://www.offsec.com/labs/](https://www.offsec.com/labs/)
    - HTB Pro Labs (enterprise‑like networks) — [https://academy.hackthebox.com/](https://academy.hackthebox.com/) and [https://app.hackthebox.com/pro-labs](https://app.hackthebox.com/pro-labs)
    - INE/Altered Security AD labs — [https://www.alteredsecurity.com/](https://www.alteredsecurity.com/) and [https://ine.com/](https://ine.com/)
- Vulnerable apps/VMs for your home lab
    - Metasploitable 2/3 (Rapid7), OWASP Juice Shop, DVWA, WebGoat, OWASP Broken Web Apps.

Reading and references

- Methodology & standards
    - PTES — [http://www.pentest-standard.org/](http://www.pentest-standard.org/)
    - NIST SP 800‑115 — [https://csrc.nist.gov/publications/detail/sp/800-115/final](https://csrc.nist.gov/publications/detail/sp/800-115/final)
    - OWASP Web Security Testing Guide — [https://owasp.org/www-project-web-security-testing-guide/](https://owasp.org/www-project-web-security-testing-guide/)
    - MITRE ATT&CK — [https://attack.mitre.org/](https://attack.mitre.org/)
- Web and general references
    - PortSwigger Web Security Academy — [https://portswigger.net/web-security](https://portswigger.net/web-security)
    - HackTricks (excellent practical notes) — [https://book.hacktricks.xyz/](https://book.hacktricks.xyz/)
    - PayloadsAllTheThings — [https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
    - GTFOBins — [https://gtfobins.github.io/](https://gtfobins.github.io/) and LOLBAS — [https://lolbas-project.github.io/](https://lolbas-project.github.io/)
- Books (nice-to-have)
    - Web Application Hacker’s Handbook (still foundational alongside PortSwigger), The Hacker Playbook series, Real‑World Bug Hunting.

Certs to consider (optional, practical-first)

- Beginner/practical: eJPT v2 (INE) — solid first hands-on exam.
- Mid-level: PNPT (TCM Security) — very practical, includes OSINT, AD, and reporting.
- Industry standard: OSCP (OffSec PEN‑200) — rigorous, strong signal for entry-level roles.
- Specializations:
    - Web: Burp Suite Certified Practitioner; eWPTXv2 (INE).
    - AD/Red Team: CRTP (Altered Security), CRTO (Zero Point Security).
    - Cloud: AWS Security Specialty; cloud attack paths via CloudGoat/flaws.cloud.