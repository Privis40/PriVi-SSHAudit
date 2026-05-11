# PriVi-Elite SSH Security Auditor v4.0
### SSH Configuration & Hardening Analysis Suite
**Developed by Prince Ubebe | [PriViSecurity Solutions](https://github.com/Privis40)**

---

## ⚠️ Legal Notice

> **This tool is intended ONLY for use on systems you own or have explicit written authorization to audit.**
> Unauthorized use against systems you do not own or have permission to test is a criminal offence under the Computer Misuse Act, the CFAA (Computer Fraud and Abuse Act), and equivalent cybercrime laws worldwide.
> **PriViSecurity accepts no liability for unauthorized or malicious use of this tool.**

If you are conducting a professional engagement, ensure you hold a signed **Letter of Authorization (LoA)** from the system owner before running this tool.

---

## What It Does

PriVi-Elite SSH Security Auditor is a professional SSH hardening analysis tool that audits the **configuration and cryptographic posture** of an SSH server — without attempting authentication or causing disruption to the target system.

It is designed for:
- Penetration testers conducting authorized SSH infrastructure assessments
- System administrators auditing their own SSH server configurations
- Security teams reviewing SSH posture across internal infrastructure
- Students and researchers studying SSH security in lab environments

---

## Features

| Feature | Description |
|---|---|
| 🔍 Banner Grab & Version Detection | Identifies SSH software, version, and protocol |
| 🛡️ CVE Version Analysis | Flags known CVEs matching detected OpenSSH/Dropbear versions |
| 🔐 Cipher & Algorithm Audit | Detects weak ciphers, MACs, and KEX algorithms via nmap/ssh-keyscan |
| 🧪 Configuration Observation | Detects SSHv1 support, OS/distro banner leakage |
| 📊 Risk Scoring Engine | Scores the target 0–100 with a risk grade (Low / Moderate / High / Critical) |
| 📋 PDF Audit Report | Generates a branded, client-ready PDF with all findings and recommendations |
| 🔒 Authorization Gate | Mandatory acknowledgment prompt — audit cannot proceed without confirmation |

---

## Requirements

```bash
pip install rich fpdf2
```

Additionally, for full algorithm enumeration:
- `nmap` with `ssh2-enum-algos` script (recommended)
- `ssh-keyscan` (fallback, limited)

Install nmap:
```bash
# Debian/Ubuntu
sudo apt install nmap

# RHEL/CentOS
sudo yum install nmap
```

---

## Installation

```bash
git clone https://github.com/Privis40/PriVi-Elite-V3-SSH-Auditor.git
cd PriVi-Elite-V3-SSH-Auditor
pip install -r requirements.txt
```

---

## Usage

```bash
python3 elite_ssh_auditor.py
```

The tool will:
1. Display the legal authorization gate — type `AGREE` to confirm you have permission
2. Prompt for the target IP/hostname and SSH port
3. Run the 4-phase audit automatically
4. Display findings in a Rich terminal dashboard
5. Generate a PDF report in the current directory

### Example Session

```
Target IP or Hostname: 192.168.1.100
SSH Port [22]: 22

[*] Starting SSH security audit on 192.168.1.100:22...

Phase 1/4  Banner Grab & Version Detection...    100%
Phase 2/4  CVE Version Analysis...               100%
Phase 3/4  Cipher & Algorithm Enumeration...     100%
Phase 4/4  Configuration Observation...          100%

[+] Report saved: PriVi_SSH_Audit_192_168_1_100_20260511_143022.pdf
```

---

## What This Tool Does NOT Do

To be explicit about scope:

- ❌ Does **not** attempt SSH login or credential testing
- ❌ Does **not** brute-force passwords or keys
- ❌ Does **not** exploit any vulnerability
- ❌ Does **not** install, modify, or persist anything on the target
- ❌ Does **not** disrupt or terminate SSH services

This is a **read-only, passive analysis tool** from the network perspective.

---

## Output — PDF Report Sections

1. Audit Summary (target, date, risk score, grade)
2. SSH Banner & Version Intelligence
3. Version CVE Analysis
4. Algorithm & Cipher Audit
5. Configuration Observations
6. Risk Score Breakdown
7. Hardening Recommendations
8. Legal & Scope Declaration

---

## Tested On

- Kali Linux 2024+
- Ubuntu 22.04 / 24.04
- Python 3.10+

---

## Author & Brand

**Prince Ubebe**
Cybersecurity Analyst | Security Automation Engineer 

- GitHub: [github.com/Privis40](https://github.com/Privis40)
- LinkedIn: [https://www.linkedin.com/in/prince-ubebe-291573321)
- YouTube: [@princeubebecyber](https://youtube.com/@princeubebecyber)
- HackerOne / Bugcrowd: Active researcher

---

## License

This tool is released for **authorized security research and professional use only.**
Redistribution or modification for malicious purposes is strictly prohibited.

© 2026 PriViSecurity Solutions. All rights reserved.
