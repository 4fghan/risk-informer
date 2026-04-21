import sys
import subprocess
import json
import shutil

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
    if len(sys.argv) < 2:
        print("Usage: python risk_informer.py <target> [--output filename]")
        sys.exit(1)

    target = sys.argv[1]
    output_file = None
    verbose = False
    html_output = False

    if "--output" in sys.argv:
        index = sys.argv.index("--output")
        if index + 1 < len(sys.argv):
            output_file = sys.argv[index + 1]

    if "--verbose" in sys.argv:
        verbose = True

    if "--html" in sys.argv:
        html_output = True

    run_nmap(target)

    ports = parse_nmap("scans/scan.xml")

    if not ports:
        print("[!] No open ports found or host is down.")
        return

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
                "total_ports": len(results)
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
                "total_ports": len(results)
            },
            "ports": results    
        }

        generate_html_report(report)
        print("[+] HTML report saved to report.html")

if __name__ == "__main__":
    main()

