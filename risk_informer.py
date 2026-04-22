import sys
import subprocess
import json
import shutil
import argparse

VERSION = "1.0.0"

try:
    from colorama import Fore, Style, init
    init(autoreset=True, convert=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False

from utils.parser import parse_nmap
from utils.risk import assess_risk, PORT_DETAILS, RECOMMENDATIONS

import os

def run_nmap(target):
    print(f"[+] Running Nmap scan on {target}...\n")
    
    if not shutil.which("nmap"):
        print("[!] Nmap is not installed.")
        print("[!] Install it with: brew install nmap")
        return

    os.makedirs("scans", exist_ok=True)
    
    result = subprocess.run(
        ["nmap", "-T4", "-F", "-sV", "-oX", "scans/scan.xml", target],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("[!] Nmap scan failed:")
        print(result.stderr)
        return

def color_risk(risk):
    if not COLOR_ENABLED:
        return risk

    if risk == "HIGH":
        return Fore.RED + risk
    elif risk == "MEDIUM":
        return Fore.YELLOW + risk
    elif risk == "LOW":
        return Fore.GREEN + risk
    else:
        return Fore.CYAN + risk

def generate_html_report(report, filename="report.html"):
    html = f"""
    <html>
    <head>
        <title>Risk Informer Report</title>
        <style>
            body {{ font-family: Arial; background-color: #0f172a; color: #e2e8f0; }}
            h1, h2 {{ color: #38bdf8; }}

            .card {{
                border: 1px solid #1e293b;
                padding: 10px;
                margin: 10px 0;
                border-radius: 8px;
                background-color: #020617;
            }}

            .badge {{
                padding: 4px 10px;
                border-radius: 6px;
                font-weight: bold;
                display: inline-block;
                margin-top: 5px;
            }}

.recs {{
    margin-top: 10px;
}}

.recs strong {{
    display: block;
    margin-bottom: 5px;
}}

.recs ul {{
    margin: 0;
    padding-left: 20px;
}}

.recs li {{
    margin-bottom: 4px;
}}

            .HIGH {{ background: #7f1d1d; color: #fecaca; }}
            .MEDIUM {{ background: #78350f; color: #fde68a; }}
            .LOW {{ background: #14532d; color: #bbf7d0; }}
            .INFO {{ background: #1e3a8a; color: #bfdbfe; }}
        </style>
    </head>
    <body>
        <h1>Risk Informer Report</h1>
        <h2>Target: {report['target']}</h2>

        <h3>Summary</h3>
        <p>High: {report['summary']['high']}</p>
        <p>Medium: {report['summary']['medium']}</p>
        <p>Low: {report['summary']['low']}</p>
        <p>Total Ports: {report['summary']['total_ports']}</p>
        <p>Risk Score: {report['summary']['risk_score']} ({report['summary']['risk_level']})</p>

        <h3>Findings</h3>
    """

    for p in report["ports"]:
        html += f"""
<div class="card">
    <strong>Port {p['port']} ({p['service']})</strong><br>
    <span class="badge {p['risk']}">{p['risk']}</span><br>
    {p['message']}
"""

        recs = RECOMMENDATIONS.get(str(p["port"]), [])
        if recs:
            html += '<div class="recs"><strong>Recommendations</strong><ul>'
            for r in recs:
                html += f"<li>{r}</li>"
            html += "</ul></div>"

        html += "</div>"

    html += "</body></html>"

    with open(filename, "w") as f:
        f.write(html)

def main():
    parser = argparse.ArgumentParser(
        description="Risk Informer - Analyze open ports and assess risk using Nmap",
        epilog="""
Examples:
  python3 risk_informer.py scanme.nmap.org
  python3 risk_informer.py 192.168.1.1 --verbose
  python3 risk_informer.py example.com --html
  python3 risk_informer.py target.com --output report.json

Tip:
  Use --verbose for detailed risks and recommendations.
""",
    formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("target", nargs="?", help="Target domain or IP address")
    parser.add_argument("--output", metavar="FILE", help="Save JSON report to file")    
    parser.add_argument("--verbose", action="store_true", help="Show detailed risks and recommendations")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument(
        "--version",
        action="version",
        version=f"Risk Informer v{VERSION}"
    )

    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        return

    target = args.target
    output_file = args.output
    verbose = args.verbose
    html_output = args.html

    run_nmap(target)

    ports = parse_nmap("scans/scan.xml")

    if not ports:
        print("[!] No open ports found or host is down.")
        return


    services = [service.lower() for _, service in ports]

    print("\n[!] Exposure Warnings:")

    warnings = []

    if len(ports) > 10:
        warnings.append("High number of open ports detected — possible overexposure")

    if "ftp" in services:
        warnings.append("FTP exposed — check for anonymous login")

    if "http" in services and "https" not in services:
        warnings.append("HTTP without HTTPS detected")

    if "ssh" in services:
        warnings.append("SSH exposed — ensure key-based authentication")

    if warnings:
        for w in warnings:
            print(f"  - {w}")
    else:
        print("  No major exposure risks detected")

    print(f"\n[+] Scan Results for {target}\n")
    
    high = 0
    medium = 0
    results = []

    for port, service in ports:
        risk, message = assess_risk(port, service)
        
        colored_risk = color_risk(risk)
        
        print(f"Port {port} ({service}) → OPEN → {colored_risk} RISK")
        print(f"  ↳ {message}")
        
        if verbose:
            details = PORT_DETAILS.get(str(port), [])
            if details:
                print("  ↳ Potential Risks:")
                for d in details:
                    print(f"     - {d}")
            
            recs = RECOMMENDATIONS.get(str(port), [])
            if recs:
                print("  ↳ Recommendations:")
                for r in recs:
                    print(f"     - {r}")   

        results.append({
            "port": int(port),
            "service": service,
            "risk": risk,
            "message": message
         })

        if risk == "HIGH":
            high += 1
        elif risk == "MEDIUM":
            medium += 1

    low = sum(1 for r in results if r["risk"] == "LOW")       

    score = 0
    for r in results:
        if r["risk"] == "HIGH":
            score += 25
        elif r["risk"] == "MEDIUM":
            score += 15
        elif r["risk"] == "LOW":
            score += 5
        elif r["risk"] == "INFO":
            score += 1

    score += len(warnings) * 10
    score = min(score, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    print(f"\n[+] Risk Score: {score}/100 ({level})")

    print("\n[+] Summary:")
    print(f"High Risk: {high}")
    print(f"Medium Risk: {medium}")

    if output_file:
        low = sum(1 for r in results if r["risk"] == "LOW")
    
        report = {
            "target": target,
            "summary": {
                "high": high,
                "medium": medium,
                "low": low,
                "total_ports": len(results),
                "risk_score": score,
                "risk_level": level
            },
            "ports": results
        }

        with open(output_file, "w") as f:
            json.dump(report, f, indent=4)

        print(f"\n[+] Report saved to {output_file}")

    if html_output:
        report = {
            "target": target,
            "summary": {
                "high": high,
                "medium": medium,
                "low": sum(1 for r in results if r["risk"] == "LOW"),
                "total_ports": len(results),
                "risk_score": score,
                "risk_level": level
                
            },
            "ports": results    
        }

        generate_html_report(report)
        print("[+] HTML report saved to report.html")
if __name__ == "__main__":
    main()

