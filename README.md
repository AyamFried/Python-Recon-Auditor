# Python Passive Recon Auditor 🔍

An automated, passive web reconnaissance and information-gathering tool built in Python. This tool is designed to automate the initial phases of a penetration test by analyzing public-facing server configurations without sending aggressive or intrusive payloads.

## 🎯 Project Overview
During the reconnaissance phase of a penetration test, security analysts must map out the target's attack surface. Instead of relying entirely on black-box commercial tools, I developed this custom CLI application using Python's `requests` and `argparse` libraries to programmatically extract and log vital target information.

## ⚙️ Core Features
* **Security Header Analysis:** Validates the presence of defensive HTTP headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`) to identify client-side vulnerabilities.
* **Information Disclosure Detection:** Parses server responses for exposed technology stacks and version numbers (e.g., `Server`, `X-Powered-By` headers).
* **Hidden Path Extraction:** Automatically locates and parses `robots.txt` to extract `Disallow` rules, revealing restricted administrative or API directories.
* **Automated JSON Reporting:** Generates a structured `.json` artifact of all findings categorized by severity for easy integration into larger penetration testing reports.

## 🛠️ Installation & Setup
This tool requires Python 3.x. It is recommended to run this within a virtual environment.

```bash
# 1. Clone the repository
git clone [https://github.com/AyamFried/Python-Recon-Auditor.git](https://github.com/AyamFried/Python-Recon-Auditor.git)
cd Python-Recon-Auditor

# 2. Create and activate a virtual environment (Windows)
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install requests

🚀 Usage

The tool accepts any valid URL via the -u or --url argument. Because the tool strictly performs passive HTTP GET requests, it is safe for general external reconnaissance.
Bash

python recon_auditor.py -u google.com

⚖️ Legal Disclaimer

This tool was built for educational purposes and ethical security research. It performs passive HTTP requests and does not execute active exploits. Users are responsible for ensuring they have authorization before auditing external systems.