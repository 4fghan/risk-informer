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
- Verbose mode with detailed risks and recommendations
- JSON report output
- HTML report generation

## Usage

```bash
python3 risk_informer.py scanme.nmap.org
python3 risk_informer.py scanme.nmap.org --verbose
python3 risk_informer.py scanme.nmap.org --html
```

Replace scanme.nmap.org with your target domain or IP.

## Example Output

See `sample_report.html` for a full HTML report example.
