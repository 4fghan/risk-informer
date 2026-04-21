       .__        __     .__        _____                                  
_______|__| _____|  | __ |__| _____/ ____\___________  _____   ___________ 
\_  __ \  |/  ___/  |/ / |  |/    \   __\/  _ \_  __ \/     \_/ __ \_  __ \
 |  | \/  |\___ \|    <  |  |   |  \  | (  <_> )  | \/  Y Y  \  ___/|  | \/
 |__|  |__/____  >__|_ \ |__|___|  /__|  \____/|__|  |__|_|  /\___  >__|   
               \/     \/         \/                        \/     \/       

# Risk Informer

A lightweight cybersecurity tool that scans targets using Nmap and provides risk-based analysis of open ports and services.

## Features
- Port scanning with Nmap
- Risk classification (High, Medium, Low, Info)
- Verbose mode with detailed risks and recommendations
- JSON report output
- HTML report generation

## Usage

```bash
python3 risk_informer.py scanme.nmap.org
python3 risk_informer.py scanme.nmap.org --verbose
python3 risk_informer.py scanme.nmap.org --html
