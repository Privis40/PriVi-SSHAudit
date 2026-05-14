#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║       PriVi-Elite SSH Security Auditor v4.0                      ║
║       SSH Configuration & Hardening Analysis Suite               ║
║       Developed by Prince Ubebe | PriViSecurity                  ║
╚══════════════════════════════════════════════════════════════════╝

LEGAL NOTICE:
  This tool is intended ONLY for use on systems you own or have
  explicit written authorization to test. Unauthorized use against
  systems you do not own or have permission to audit is illegal
  under the Computer Misuse Act, CFAA, and equivalent laws
  worldwide. PriViSecurity accepts no liability for misuse.
"""

import socket
import sys
import os
import re
import time
import threading
import subprocess
from datetime import datetime
from fpdf import FPDF
from fpdf.enums import XPos, YPos

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.prompt import Prompt, IntPrompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

# ── CONSTANTS ─────────────────────────────────────────────────────────────────

AUTHOR   = "Prince Ubebe"
BRAND    = "PriViSecurity"
VERSION  = "4.0"
TOOL     = "PriVi-Elite SSH Auditor"

# SSH versions with known critical vulnerabilities
VULNERABLE_VERSIONS = {
    "OpenSSH_7.2": "CVE-2016-6210 (User Enumeration), CVE-2016-0778 (Buffer Overflow)",
    "OpenSSH_7.1": "CVE-2016-0777 (Key Leak via roaming), CVE-2016-0778",
    "OpenSSH_6.8": "CVE-2015-5600 (Max auth bypass)",
    "OpenSSH_6.6": "CVE-2014-2532 (AcceptEnv wildcard bypass)",
    "OpenSSH_5.":  "Multiple legacy CVEs  -  severely outdated",
    "OpenSSH_4.":  "End-of-life  -  critically vulnerable",
    "OpenSSH_3.":  "End-of-life  -  critically vulnerable",
    "dropbear_20": "Outdated Dropbear  -  check vendor for CVEs",
}

# Weak ciphers/algorithms to flag
WEAK_CIPHERS = [
    "arcfour", "arcfour128", "arcfour256",     # RC4  -  broken
    "aes128-cbc", "aes192-cbc", "aes256-cbc",  # CBC mode  -  vulnerable to BEAST
    "3des-cbc", "blowfish-cbc",                 # Legacy/weak
    "cast128-cbc",
    "rijndael-cbc@lysator.liu.se",
]

WEAK_MACS = [
    "hmac-md5", "hmac-md5-96",
    "hmac-sha1-96",
    "umac-32@openssh.com",
]

WEAK_KEX = [
    "diffie-hellman-group1-sha1",   # Logjam vulnerable
    "diffie-hellman-group14-sha1",  # SHA-1 deprecated
    "gss-group1-sha1-*",
]

SAFE_CIPHERS = [
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr", "aes192-ctr", "aes128-ctr",
]

SAFE_KEX = [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "ecdh-sha2-nistp256",
]

# Port 22 default banner format
SSH_BANNER_RE = re.compile(r"SSH-(\d+\.\d+)-(.+)", re.IGNORECASE)


# ── AUTHORIZATION GATE ────────────────────────────────────────────────────────

def authorization_gate():
    """
    Mandatory authorization acknowledgment.
    User must confirm they have written permission before proceeding.
    """
    os.system("clear")

    gate_text = Text()
    gate_text.append("\n  ⚠️  LEGAL AUTHORIZATION REQUIRED\n\n", style="bold red")
    gate_text.append(
        "  This tool performs active SSH security analysis against a target system.\n"
        "  You MUST have one of the following before proceeding:\n\n",
        style="white"
    )
    gate_text.append("    ✔  You own the target system, OR\n", style="green")
    gate_text.append("    ✔  You hold a signed Letter of Authorization (LoA)\n", style="green")
    gate_text.append("       from the system owner permitting this audit.\n\n", style="green")
    gate_text.append(
        "  Unauthorized use is a criminal offence under the Computer Misuse Act,\n"
        "  CFAA, and equivalent cybercrime laws worldwide.\n\n",
        style="dim white"
    )
    gate_text.append("  PriViSecurity accepts NO liability for unauthorized use.\n\n", style="dim red")

    console.print(Panel(gate_text, border_style="red", title="[bold red]PriVi-Elite SSH Auditor v4.0[/bold red]"))

    console.print("[bold white]Do you have written authorization to audit the target system?[/bold white]")
    console.print("[dim]Type [bold green]AGREE[/bold green] to confirm and proceed, or press Ctrl+C to exit.[/dim]\n")

    try:
        response = input("  > ").strip()
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Session cancelled.[/bold yellow]")
        sys.exit(0)

    if response != "AGREE":
        console.print("\n[bold red][!] Authorization not confirmed. Exiting.[/bold red]")
        sys.exit(0)

    console.print("\n[bold green][✔] Authorization confirmed. Proceeding with audit.[/bold green]\n")
    time.sleep(1)


# ── HEADER ────────────────────────────────────────────────────────────────────

def print_header():
    os.system("clear")
    header = Text()
    header.append(
        "\n"
        "  ██████╗ ██████╗ ██╗██╗   ██╗██╗███████╗███████╗ ██████╗\n"
        "  ██╔══██╗██╔══██╗██║██║   ██║██║██╔════╝██╔════╝██╔════╝\n"
        "  ██████╔╝██████╔╝██║██║   ██║██║███████╗███████╗██║\n"
        "  ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██║╚════██║██╔════╝██║\n"
        "  ██║     ██║  ██║██║ ╚████╔╝ ██║███████║██║     ╚██████╗\n"
        "  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═╝╚══════╝╚═╝      ╚═════╝\n",
        style="bold cyan"
    )
    header.append(
        f"  {BRAND}  |  {TOOL} v{VERSION}  |  SSH Configuration & Hardening Analysis\n",
        style="dim white"
    )
    header.append(f"  Developer: {AUTHOR}\n", style="dim white")
    console.print(Panel(header, border_style="blue"))


# ── SSH BANNER GRAB ───────────────────────────────────────────────────────────

def grab_ssh_banner(host: str, port: int, timeout: int = 5) -> dict:
    """
    Connect to SSH port and grab the server banner.
    Returns version info and raw banner string.
    """
    result = {
        "raw_banner": None,
        "protocol_version": None,
        "software": None,
        "reachable": False,
        "error": None,
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.close()

        result["raw_banner"] = banner
        result["reachable"] = True

        match = SSH_BANNER_RE.match(banner)
        if match:
            result["protocol_version"] = match.group(1)
            result["software"] = match.group(2)

    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused  -  SSH may not be running on this port"
    except socket.gaierror:
        result["error"] = "Hostname resolution failed"
    except Exception as e:
        result["error"] = str(e)

    return result


# ── VERSION CVE CHECK ─────────────────────────────────────────────────────────

def check_version_cves(software: str) -> list:
    """
    Check software string against known vulnerable version patterns.
    Returns list of (version_pattern, cve_info) matches.
    """
    findings = []
    if not software:
        return findings
    for pattern, cve_info in VULNERABLE_VERSIONS.items():
        if pattern.lower() in software.lower():
            findings.append({
                "pattern": pattern,
                "cve": cve_info,
                "severity": "CRITICAL" if "critically" in cve_info.lower() or pattern in ("OpenSSH_4.", "OpenSSH_3.") else "HIGH",
            })
    return findings


# ── ALGORITHM AUDIT VIA SSH-KEYSCAN / NMAP ────────────────────────────────────

def audit_algorithms(host: str, port: int) -> dict:
    """
    Use ssh-keyscan or nmap (if available) to enumerate supported
    ciphers, MACs, and KEX algorithms. Falls back gracefully.
    """
    result = {
        "ciphers": [],
        "macs": [],
        "kex": [],
        "host_keys": [],
        "weak_ciphers": [],
        "weak_macs": [],
        "weak_kex": [],
        "method": None,
        "raw_output": "",
    }

    # Try nmap ssh2-enum-algos script first
    try:
        nmap_check = subprocess.run(
            ["which", "nmap"], capture_output=True, text=True, timeout=3
        )
        if nmap_check.returncode == 0:
            nmap_out = subprocess.run(
                ["nmap", "-p", str(port), "--script", "ssh2-enum-algos", host],
                capture_output=True, text=True, timeout=30
            )
            output = nmap_out.stdout
            result["raw_output"] = output
            result["method"] = "nmap ssh2-enum-algos"

            # Parse nmap output
            section = None
            for line in output.splitlines():
                line = line.strip()
                if "encryption_algorithms" in line.lower():
                    section = "ciphers"
                elif "mac_algorithms" in line.lower():
                    section = "macs"
                elif "kex_algorithms" in line.lower():
                    section = "kex"
                elif "server_host_key_algorithms" in line.lower():
                    section = "host_keys"
                elif line.startswith("|") and section:
                    alg = line.lstrip("|").strip()
                    if alg:
                        result[section].append(alg)

            # Flag weak ones
            result["weak_ciphers"] = [c for c in result["ciphers"] if c in WEAK_CIPHERS]
            result["weak_macs"]    = [m for m in result["macs"] if m in WEAK_MACS]
            result["weak_kex"]     = [k for k in result["kex"] if k in WEAK_KEX]
            return result

    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: ssh-keyscan for host key types only
    try:
        keyscan_check = subprocess.run(
            ["which", "ssh-keyscan"], capture_output=True, text=True, timeout=3
        )
        if keyscan_check.returncode == 0:
            ks_out = subprocess.run(
                ["ssh-keyscan", "-p", str(port), "-t", "rsa,ecdsa,ed25519,dsa", host],
                capture_output=True, text=True, timeout=10
            )
            for line in ks_out.stdout.splitlines():
                if not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2:
                        result["host_keys"].append(parts[1])
            result["method"] = "ssh-keyscan (limited)"

            # Flag DSA  -  deprecated
            if any("ssh-dss" in k or "dsa" in k for k in result["host_keys"]):
                result["weak_kex"].append("ssh-dss host key (DSA deprecated  -  RFC 8308)")

    except (FileNotFoundError, subprocess.TimeoutExpired):
        result["method"] = "unavailable"

    return result


# ── CONFIGURATION PROBE ───────────────────────────────────────────────────────

def probe_ssh_config(host: str, port: int, timeout: int = 5) -> dict:
    """
    Probe observable SSH server behaviors without authentication:
    - Protocol version (SSHv1 detection)
    - Banner verbosity (info leakage)
    - Keyboard-interactive availability hint
    - Max connection handling
    """
    result = {
        "sshv1_supported": False,
        "banner_leaks_os": False,
        "banner_leaks_distro": False,
        "debian_banner": False,
        "ubuntu_banner": False,
        "os_hints": [],
    }

    try:
        # Test SSHv1  -  any response to SSHv1 init is a flag
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()

        # Check OS leakage in banner
        banner_lower = banner.lower()
        if "debian" in banner_lower:
            result["debian_banner"] = True
            result["banner_leaks_distro"] = True
            result["os_hints"].append("Debian Linux (from banner)")
        if "ubuntu" in banner_lower:
            result["ubuntu_banner"] = True
            result["banner_leaks_distro"] = True
            result["os_hints"].append("Ubuntu Linux (from banner)")
        if "freebsd" in banner_lower:
            result["banner_leaks_distro"] = True
            result["os_hints"].append("FreeBSD (from banner)")
        if "centos" in banner_lower or "rhel" in banner_lower:
            result["banner_leaks_distro"] = True
            result["os_hints"].append("RHEL/CentOS (from banner)")

        # Try sending SSHv1 identification
        sock.send(b"SSH-1.5-PriViAudit\r\n")
        try:
            v1_resp = sock.recv(256).decode("utf-8", errors="replace")
            if "SSH-" in v1_resp and "1." in v1_resp:
                result["sshv1_supported"] = True
        except Exception:
            pass

        sock.close()

    except Exception:
        pass

    return result


# ── SCORING ENGINE ────────────────────────────────────────────────────────────

def compute_risk_score(banner_info: dict, version_cves: list,
                       algo_audit: dict, config_probe: dict) -> dict:
    """
    Compute an overall risk score (0-100, lower = more risk).
    Returns score, grade, and breakdown.
    """
    score = 100
    deductions = []

    # Version CVEs
    for finding in version_cves:
        if finding["severity"] == "CRITICAL":
            score -= 30
            deductions.append(f"-30  Known critical CVEs in {finding['pattern']}")
        else:
            score -= 20
            deductions.append(f"-20  Known high-severity CVEs in {finding['pattern']}")

    # SSHv1
    if config_probe.get("sshv1_supported"):
        score -= 25
        deductions.append("-25  SSHv1 supported (cryptographically broken)")

    # Weak ciphers
    if algo_audit.get("weak_ciphers"):
        penalty = min(20, len(algo_audit["weak_ciphers"]) * 5)
        score -= penalty
        deductions.append(f"-{penalty}  Weak ciphers supported ({', '.join(algo_audit['weak_ciphers'][:3])})")

    # Weak KEX
    if algo_audit.get("weak_kex"):
        penalty = min(15, len(algo_audit["weak_kex"]) * 5)
        score -= penalty
        deductions.append(f"-{penalty}  Weak key exchange algorithms ({', '.join(algo_audit['weak_kex'][:2])})")

    # Weak MACs
    if algo_audit.get("weak_macs"):
        penalty = min(10, len(algo_audit["weak_macs"]) * 3)
        score -= penalty
        deductions.append(f"-{penalty}  Weak MAC algorithms ({', '.join(algo_audit['weak_macs'][:2])})")

    # OS/distro banner leakage
    if config_probe.get("banner_leaks_distro"):
        score -= 5
        deductions.append("-5   OS/distro info leaked via banner")

    # Protocol version
    if banner_info.get("protocol_version") == "1.99":
        score -= 10
        deductions.append("-10  Protocol 1.99 (supports SSHv1 fallback)")

    score = max(0, score)

    if score >= 80:
        grade, color = "LOW RISK", "green"
    elif score >= 60:
        grade, color = "MODERATE RISK", "yellow"
    elif score >= 40:
        grade, color = "HIGH RISK", "red"
    else:
        grade, color = "CRITICAL RISK", "bold red"

    return {
        "score": score,
        "grade": grade,
        "color": color,
        "deductions": deductions,
    }


# ── PDF REPORT ────────────────────────────────────────────────────────────────

class PriViSSHReport(FPDF):
    def header(self):
        # Navy header bar
        self.set_fill_color(26, 26, 46)
        self.rect(0, 0, 210, 38, "F")
        self.set_xy(10, 8)
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, "PriVi-Elite SSH Security Audit Report",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_xy(10, 20)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(180, 180, 180)
        self.cell(0, 8, f"PriViSecurity  |  {TOOL} v{VERSION}",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(18)

    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()}   -   Confidential: Authorized Use Only   -   PriViSecurity", align="C")

    def section_title(self, title: str):
        self.set_fill_color(196, 30, 58)   # PriVi accent red
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 9, f"  {title}", fill=True,new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def key_value(self, key: str, value: str, highlight: bool = False):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(60, 60, 60)
        self.cell(55, 7, f"  {key}:",new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 9)
        if highlight:
            self.set_text_color(196, 30, 58)
        else:
            self.set_text_color(0, 0, 0)
        self.cell(0, 7, value,new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)

    def finding_row(self, severity: str, description: str):
        colors = {
            "CRITICAL": (220, 50, 50),
            "HIGH": (220, 100, 30),
            "MEDIUM": (200, 160, 0),
            "INFO": (60, 100, 180),
        }
        rgb = colors.get(severity, (100, 100, 100))
        self.set_font("Helvetica", "B", 8)
        self.set_fill_color(*rgb)
        self.set_text_color(255, 255, 255)
        self.cell(22, 6, f"  {severity}", fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 8)
        self.set_fill_color(245, 245, 245)
        self.set_text_color(30, 30, 30)
        self.cell(0, 6, f"  {description}", fill=True,new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)


def generate_pdf_report(target: str, port: int, banner_info: dict,
                        version_cves: list, algo_audit: dict,
                        config_probe: dict, risk: dict,
                        operator: dict = None) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace(":", "_")
    filename = f"PriVi_SSH_Audit_{safe_target}_{timestamp}.pdf"

    pdf = PriViSSHReport()
    pdf.add_page()

    # ── Cover info ──
    pdf.section_title("1. Audit Summary")
    pdf.key_value("Target Host", target)
    pdf.key_value("SSH Port", str(port))
    pdf.key_value("Audit Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    pdf.key_value("Risk Grade", risk["grade"], highlight=risk["grade"] in ("HIGH RISK", "CRITICAL RISK"))
    pdf.key_value("Risk Score", f"{risk['score']}/100")
    pdf.ln(4)

    # Score bar
    score_pct = risk["score"]
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(55, 7, "  Security Score:",new_x=XPos.RIGHT, new_y=YPos.TOP)
    bar_x = pdf.get_x()
    bar_y = pdf.get_y()
    pdf.set_fill_color(220, 220, 220)
    pdf.rect(bar_x, bar_y + 1, 100, 5, "F")
    if score_pct >= 80:
        pdf.set_fill_color(30, 180, 60)
    elif score_pct >= 60:
        pdf.set_fill_color(200, 160, 0)
    else:
        pdf.set_fill_color(196, 30, 58)
    pdf.rect(bar_x, bar_y + 1, score_pct, 5, "F")
    pdf.ln(10)

    # ── Banner ──
    pdf.section_title("2. SSH Banner & Version Intelligence")
    if banner_info.get("reachable"):
        pdf.key_value("Raw Banner", banner_info.get("raw_banner", "N/A"))
        pdf.key_value("Protocol Version", banner_info.get("protocol_version", "Unknown"))
        pdf.key_value("Server Software", banner_info.get("software", "Unknown"))
    else:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 7, f"  Target unreachable: {banner_info.get('error', 'Unknown error')}",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # ── CVEs ──
    pdf.section_title("3. Version CVE Analysis")
    if version_cves:
        for cve in version_cves:
            pdf.finding_row(cve["severity"], f"{cve['pattern']}  -  {cve['cve']}")
    else:
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 7, "  No known CVEs matched for detected version.",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # ── Algorithms ──
    pdf.section_title("4. Algorithm & Cipher Audit")
    if algo_audit.get("method") and algo_audit["method"] != "unavailable":
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 6, f"  Detection method: {algo_audit['method']}",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

        if algo_audit["weak_ciphers"]:
            for c in algo_audit["weak_ciphers"]:
                pdf.finding_row("HIGH", f"Weak cipher supported: {c}")
        if algo_audit["weak_macs"]:
            for m in algo_audit["weak_macs"]:
                pdf.finding_row("MEDIUM", f"Weak MAC supported: {m}")
        if algo_audit["weak_kex"]:
            for k in algo_audit["weak_kex"]:
                pdf.finding_row("HIGH", f"Weak key exchange: {k}")
        if not any([algo_audit["weak_ciphers"], algo_audit["weak_macs"], algo_audit["weak_kex"]]):
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 7, "  No weak algorithms detected.",new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        if algo_audit["host_keys"]:
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 6, "  Supported Host Key Types:",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", "", 9)
            for hk in algo_audit["host_keys"]:
                pdf.cell(0, 5, f"    - {hk}",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 7, "  Algorithm audit unavailable  -  nmap/ssh-keyscan not found.",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    # ── Config probe ──
    pdf.section_title("5. Configuration Observations")
    if config_probe.get("sshv1_supported"):
        pdf.finding_row("CRITICAL", "SSHv1 appears supported  -  protocol is cryptographically broken")
    if config_probe.get("banner_leaks_distro"):
        for hint in config_probe.get("os_hints", []):
            pdf.finding_row("MEDIUM", f"OS/distro information leaked via banner: {hint}")
    if not config_probe.get("sshv1_supported") and not config_probe.get("banner_leaks_distro"):
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 7, "  No observable configuration issues detected.",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # ── Deductions ──
    pdf.section_title("6. Risk Score Breakdown")
    if risk["deductions"]:
        pdf.set_font("Helvetica", "", 9)
        for d in risk["deductions"]:
            pdf.cell(0, 6, f"  {d}",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 7, "  No risk deductions  -  strong configuration.",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # ── Recommendations ──
    pdf.section_title("7. Hardening Recommendations")
    recs = build_recommendations(version_cves, algo_audit, config_probe,
                                  banner_info.get("protocol_version"))
    pdf.set_font("Helvetica", "", 9)
    for i, rec in enumerate(recs, 1):
        pdf.multi_cell(0, 6, f"  {i}. {rec}")
        pdf.ln(1)

    # ── Legal ──
    pdf.add_page()
    pdf.section_title("8. Legal & Scope Declaration")
    pdf.set_font("Helvetica", "", 9)
    legal = (
        "This report was generated by PriVi-Elite SSH Security Auditor v4.0, developed by "
        "Prince Ubebe / PriViSecurity. The tool was used under the explicit authorization "
        "acknowledgment confirmed by the operator at session start.\n\n"
        "This report is confidential and intended solely for the authorized recipient. "
        "Redistribution without consent of the system owner is prohibited.\n\n"
        "PriViSecurity accepts no liability for actions taken based on the findings in this "
        "report without appropriate change-control, testing, and professional review."
    )
    pdf.multi_cell(0, 6, legal)

    pdf.output(filename)
    return filename


# ── RECOMMENDATIONS ENGINE ────────────────────────────────────────────────────

def build_recommendations(version_cves: list, algo_audit: dict,
                           config_probe: dict, proto_ver: str) -> list:
    recs = []

    if version_cves:
        recs.append(
            "Upgrade OpenSSH to the latest stable release. Current version has known "
            "CVEs  -  patch immediately and subscribe to OpenSSH security advisories."
        )

    if config_probe.get("sshv1_supported"):
        recs.append(
            "Disable SSHv1 entirely. Add 'Protocol 2' to /etc/ssh/sshd_config. "
            "SSHv1 is cryptographically broken and should never be enabled."
        )

    if proto_ver == "1.99":
        recs.append(
            "Protocol version 1.99 indicates SSHv1 fallback is enabled. "
            "Set 'Protocol 2' in sshd_config to enforce SSHv2 only."
        )

    if algo_audit.get("weak_ciphers"):
        recs.append(
            f"Remove weak ciphers from sshd_config: {', '.join(algo_audit['weak_ciphers'])}. "
            f"Recommended safe ciphers: {', '.join(SAFE_CIPHERS[:3])}."
        )

    if algo_audit.get("weak_kex"):
        recs.append(
            f"Remove weak KEX algorithms: {', '.join(algo_audit['weak_kex'])}. "
            f"Recommended: {', '.join(SAFE_KEX[:3])}."
        )

    if algo_audit.get("weak_macs"):
        recs.append(
            f"Remove weak MAC algorithms: {', '.join(algo_audit['weak_macs'])}. "
            "Use hmac-sha2-256 or hmac-sha2-512 only."
        )

    if config_probe.get("banner_leaks_distro"):
        recs.append(
            "Suppress OS/distro information from the SSH banner. "
            "Set a neutral banner or use 'DebianBanner no' in sshd_config. "
            "OS fingerprinting via banner aids attackers in targeting known CVEs."
        )

    if any("dsa" in k.lower() or "ssh-dss" in k.lower()
           for k in algo_audit.get("host_keys", [])):
        recs.append(
            "DSA host keys are deprecated (RFC 8308). Regenerate host keys using "
            "Ed25519 ('ssh-keygen -t ed25519') and remove DSA keys."
        )

    if not recs:
        recs.append(
            "No major issues detected. Maintain this configuration, keep OpenSSH "
            "updated, and review CIS SSH Benchmark periodically."
        )

    # Universal hardening recommendations
    recs.append(
        "Ensure PasswordAuthentication is set to 'no' in sshd_config and use "
        "SSH key-based authentication exclusively for privileged accounts."
    )
    recs.append(
        "Set MaxAuthTries to 3 or lower, enable fail2ban or equivalent intrusion "
        "prevention, and restrict SSH access to known source IPs via AllowUsers "
        "or firewall rules."
    )
    recs.append(
        "Disable root login over SSH: set 'PermitRootLogin no' in sshd_config. "
        "Use a non-root account with sudo escalation instead."
    )

    return recs


# ── MAIN AUDIT ENGINE ─────────────────────────────────────────────────────────

def run_audit(target: str, port: int, operator: dict = None):
    """
    Orchestrate the full SSH audit with Rich Live progress display.
    """
    print_header()

    results = {
        "banner": {},
        "cves": [],
        "algos": {},
        "config": {},
        "risk": {},
    }
    log_lines = []

    def log(msg):
        log_lines.append(f"[{time.strftime('%H:%M:%S')}] {msg}")

    layout = Layout()
    layout.split_column(
        Layout(name="progress", size=10),
        Layout(name="log",      size=14),
    )

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="cyan"),
        TextColumn("[bold white]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:

        # Phase 1  -  Banner grab
        t1 = progress.add_task("[cyan]Phase 1/4  Banner Grab & Version Detection...", total=100)
        log(f"Connecting to {target}:{port}...")
        results["banner"] = grab_ssh_banner(target, port)
        if results["banner"]["reachable"]:
            log(f"[+] Banner: {results['banner']['raw_banner']}")
            log(f"[+] Software: {results['banner']['software']}")
        else:
            log(f"[!] {results['banner']['error']}")
        progress.update(t1, completed=100)

        if not results["banner"]["reachable"]:
            console.print(f"\n[bold red][!] Target unreachable: {results['banner']['error']}[/bold red]")
            return

        # Phase 2  -  CVE check
        t2 = progress.add_task("[cyan]Phase 2/4  CVE Version Analysis...", total=100)
        results["cves"] = check_version_cves(results["banner"]["software"])
        if results["cves"]:
            for c in results["cves"]:
                log(f"[!] CVE MATCH: {c['pattern']}  -  {c['cve'][:50]}...")
        else:
            log("[+] No CVE patterns matched for detected version.")
        progress.update(t2, completed=100)

        # Phase 3  -  Algorithm audit
        t3 = progress.add_task("[cyan]Phase 3/4  Cipher & Algorithm Enumeration...", total=100)
        log("Enumerating supported algorithms...")
        results["algos"] = audit_algorithms(target, port)
        log(f"[+] Method: {results['algos'].get('method', 'unavailable')}")
        if results["algos"]["weak_ciphers"]:
            log(f"[!] Weak ciphers: {', '.join(results['algos']['weak_ciphers'])}")
        if results["algos"]["weak_kex"]:
            log(f"[!] Weak KEX: {', '.join(results['algos']['weak_kex'])}")
        progress.update(t3, completed=100)

        # Phase 4  -  Config probe
        t4 = progress.add_task("[cyan]Phase 4/4  Configuration Observation...", total=100)
        log("Probing observable configuration...")
        results["config"] = probe_ssh_config(target, port)
        if results["config"]["sshv1_supported"]:
            log("[!!] CRITICAL: SSHv1 appears supported!")
        if results["config"]["banner_leaks_distro"]:
            log(f"[!] OS info leaked: {', '.join(results['config']['os_hints'])}")
        progress.update(t4, completed=100)

    # Compute risk
    results["risk"] = compute_risk_score(
        results["banner"], results["cves"], results["algos"], results["config"]
    )

    # ── Display results ──────────────────────────────────────────────────────
    os.system("clear")
    print_header()

    # Summary panel
    risk = results["risk"]
    summary = Table(show_header=False, box=None, padding=(0, 2))
    summary.add_column(style="bold white", width=22)
    summary.add_column()
    summary.add_row("Target",          f"[cyan]{target}:{port}[/cyan]")
    summary.add_row("Raw Banner",      results["banner"].get("raw_banner", "N/A"))
    summary.add_row("SSH Software",    results["banner"].get("software", "Unknown"))
    summary.add_row("Protocol",        results["banner"].get("protocol_version", "Unknown"))
    summary.add_row("Risk Score",      f"[{risk['color']}]{risk['score']}/100[/{risk['color']}]")
    summary.add_row("Risk Grade",      f"[{risk['color']}]{risk['grade']}[/{risk['color']}]")
    console.print(Panel(summary, title="[bold cyan]Audit Summary[/bold cyan]", border_style="blue"))

    # Findings table
    findings_table = Table(title="Security Findings", border_style="red", show_lines=True)
    findings_table.add_column("Severity", style="bold", width=12)
    findings_table.add_column("Finding", style="white")

    if results["cves"]:
        for c in results["cves"]:
            findings_table.add_row(
                f"[bold red]{c['severity']}[/bold red]",
                f"Version CVE: {c['pattern']}  -  {c['cve'][:80]}"
            )

    if results["config"]["sshv1_supported"]:
        findings_table.add_row("[bold red]CRITICAL[/bold red]", "SSHv1 supported  -  protocol is cryptographically broken")

    for wc in results["algos"].get("weak_ciphers", []):
        findings_table.add_row("[bold yellow]HIGH[/bold yellow]", f"Weak cipher supported: {wc}")

    for wk in results["algos"].get("weak_kex", []):
        findings_table.add_row("[bold yellow]HIGH[/bold yellow]", f"Weak key exchange: {wk}")

    for wm in results["algos"].get("weak_macs", []):
        findings_table.add_row("[yellow]MEDIUM[/yellow]", f"Weak MAC algorithm: {wm}")

    if results["config"].get("banner_leaks_distro"):
        for hint in results["config"]["os_hints"]:
            findings_table.add_row("[yellow]MEDIUM[/yellow]", f"OS info leaked via banner: {hint}")

    if findings_table.row_count == 0:
        findings_table.add_row("[green]NONE[/green]", "No security issues detected  -  strong configuration.")

    console.print(findings_table)

    # Risk breakdown
    if risk["deductions"]:
        breakdown = Table(title="Risk Score Breakdown", border_style="blue", show_lines=False)
        breakdown.add_column("Deduction", style="dim white")
        for d in risk["deductions"]:
            breakdown.add_row(d)
        console.print(breakdown)

    # Recommendations
    recs = build_recommendations(results["cves"], results["algos"],
                                  results["config"],
                                  results["banner"].get("protocol_version"))
    rec_text = Text()
    rec_text.append("Hardening Recommendations\n\n", style="bold white")
    for i, r in enumerate(recs, 1):
        rec_text.append(f"  {i}. ", style="bold cyan")
        rec_text.append(f"{r}\n\n", style="white")
    console.print(Panel(rec_text, border_style="green", title="[bold green]Recommendations[/bold green]"))

    # Generate PDF
    console.print("\n[bold cyan][*] Generating PDF audit report...[/bold cyan]")
    try:
        pdf_file = generate_pdf_report(
            target, port,
            results["banner"], results["cves"],
            results["algos"], results["config"], risk,
            operator
        )
        console.print(f"[bold green][+] Report saved: {pdf_file}[/bold green]")
    except Exception as e:
        console.print(f"[bold red][!] PDF generation failed: {e}[/bold red]")


# ── ENTRY POINT ───────────────────────────────────────────────────────────────


def get_operator_info() -> dict:
    """
    Prompt for operator name and organization.
    Appears in the PDF report as "Conducted by".
    PriViSecurity brand and Prince Ubebe developer credit
    remain fixed in the report header — always.
    """
    console.print(Panel(
        "\n  [bold white]Operator Details[/bold white]\n\n"
        "  These will appear in the PDF report footer.\n"
        "  [dim]PriViSecurity branding stays fixed in the header.[/dim]\n",
        border_style="blue",
        title="[bold cyan]Report Configuration[/bold cyan]"
    ))
    op_name = console.input(
        "  [cyan]Your name[/cyan]          (analyst conducting this audit): "
    ).strip()
    op_org = console.input(
        "  [cyan]Organization[/cyan]       (optional, press Enter to skip):  "
    ).strip()
    if not op_name:
        op_name = "Operator"
    return {"name": op_name, "org": op_org}

def main():
    authorization_gate()
    print_header()
    operator = get_operator_info()

    console.print("[bold white]SSH Audit Target Configuration[/bold white]\n")
    target = Prompt.ask("[cyan]Target IP or Hostname[/cyan]", default="192.168.1.1")
    port   = IntPrompt.ask("[cyan]SSH Port[/cyan]", default=22)

    console.print(f"\n[bold cyan][*] Starting SSH security audit on {target}:{port}...[/bold cyan]\n")
    time.sleep(0.5)

    run_audit(target, port, operator)

    console.print("\n[bold green][✔] Audit complete. PriViSecurity standing by.[/bold green]\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Audit aborted by user.[/bold yellow]")
        sys.exit(0)
