# Risk Informer

A lightweight cybersecurity tool that scans targets using Nmap and provides risk-based analysis of open ports and services.

## Requirements

- Python 3.8+
- Nmap installed on system

## Installation

```bash
git clone https://github.com/4fghan/risk-informer.git
cd risk-informer
pip install -r requirements.txt

```

## Features

- Port scanning with Nmap  
- Risk classification (High, Medium, Low, Info)  
- Exposure detection (e.g., HTTP without HTTPS, SSH exposure)  
- Risk scoring system (0–100 rating)  
- JSON report output  
- HTML report generation  
- Verbose mode with detailed risks and recommendations  

## Usage

```bash
python3 risk_informer.py scanme.nmap.org
python3 risk_informer.py scanme.nmap.org --verbose
python3 risk_informer.py scanme.nmap.org --html
```
# Scan modes
python3 risk_informer.py scanme.nmap.org --full
python3 risk_informer.py scanme.nmap.org --stealth

Replace scanme.nmap.org with your target domain or IP.

## Example Output

See `sample_report.html` for a full HTML report example.
