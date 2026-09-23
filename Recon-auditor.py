import argparse
import requests
import json
from datetime import datetime
from urllib.parse import urljoin

class PassiveReconAuditor:
    def __init__(self, target_url: str):
        # Ensure the URL is properly formatted
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        self.target_url = target_url.rstrip('/')
        self.findings = []
        self.headers = {"User-Agent": "Seculab-Open-Recruitment-Recon/1.0"}

    def log_finding(self, title: str, category: str, severity: str, details: str):
        finding = {
            "title": title,
            "category": category,
            "severity": severity,
            "details": details,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        self.findings.append(finding)
        print(f"  [{severity}] {title} -> {details}")

    def audit_security_headers(self):
        print("\n[*] Module 1: Analyzing Security Headers...")
        try:
            res = requests.get(self.target_url, headers=self.headers, timeout=10)
            required_headers = [
                'Content-Security-Policy', 
                'X-Frame-Options', 
                'Strict-Transport-Security',
                'X-Content-Type-Options'
            ]
            
            for header in required_headers:
                if header not in res.headers:
                    self.log_finding(
                        title=f"Missing Header: {header}",
                        category="Configuration",
                        severity="LOW",
                        details="Missing defensive header exposes users to client-side attacks."
                    )
                else:
                    print(f"  [OK] {header} is present.")
        except requests.exceptions.RequestException as e:
            print(f"  [!] Connection failed: {e}")

    def audit_info_disclosure(self):
        print("\n[*] Module 2: Checking for Server Information Disclosure...")
        try:
            res = requests.get(self.target_url, headers=self.headers, timeout=10)
            
            # Attackers look for Server or X-Powered-By headers to find specific exploit versions
            for header in ['Server', 'X-Powered-By']:
                if header in res.headers:
                    self.log_finding(
                        title="Information Disclosure",
                        category="Reconnaissance",
                        severity="INFO",
                        details=f"Server exposes technology stack via '{header}': {res.headers[header]}"
                    )
        except requests.exceptions.RequestException as e:
            print(f"  [!] Connection failed: {e}")

    def audit_robots_txt(self):
        print("\n[*] Module 3: Analyzing robots.txt for hidden paths...")
        robots_url = f"{self.target_url}/robots.txt"
        try:
            res = requests.get(robots_url, headers=self.headers, timeout=10)
            if res.status_code == 200:
                print("  [OK] robots.txt found. Extracting Disallow rules...")
                disallowed_paths = [line.split(': ')[1] for line in res.text.split('\n') if line.startswith('Disallow:')]
                
                if disallowed_paths:
                    self.log_finding(
                        title="Hidden Paths Exposed",
                        category="Reconnaissance",
                        severity="INFO",
                        details=f"Found {len(disallowed_paths)} restricted paths (e.g., {disallowed_paths[0]})"
                    )
            else:
                print("  [OK] No robots.txt found.")
        except requests.exceptions.RequestException as e:
            print(f"  [!] Connection failed: {e}")

    def export_report(self):
        report_data = {
            "target": self.target_url,
            "total_findings": len(self.findings),
            "findings": self.findings
        }
        filename = f"recon_report_{self.target_url.replace('https://', '').replace('/', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=4)
        print(f"\n[+] Audit report generated successfully: {filename}")

def main():
    parser = argparse.ArgumentParser(description="Passive Web Reconnaissance Auditor")
    parser.add_argument("-u", "--url", required=True, help="Target URL to audit (e.g., example.com)")
    args = parser.parse_args()

    print(f"=== Passive Reconnaissance Audit Started ===")
    print(f"Target: {args.url}")
    
    auditor = PassiveReconAuditor(target_url=args.url)
    auditor.audit_security_headers()
    auditor.audit_info_disclosure()
    auditor.audit_robots_txt()
    
    auditor.export_report()

if __name__ == '__main__':
    main()