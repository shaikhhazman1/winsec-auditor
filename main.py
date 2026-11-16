import argparse
from core.safety import get_authorization, enforce_scope, kill_switch_check
from modules.report import correlate, write_reports

def main():
    parser = argparse.ArgumentParser(description="WinSec Auditor: Windows Compliance Scanner")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP")
    parser.add_argument("--dry-run", action="store_true", help="Simulate scan")
    args = parser.parse_args()

    # 1. Test Keselamatan
    get_authorization()
    enforce_scope(args.target)
    kill_switch_check()

    # 2. Dummy Data (Kawan kau nanti akan buat bahagian ni)
    print("[*] Scanning ports...")
    scan_results = [{"port": 445, "status": "open"}] 
    
    print("[*] Auditing compliance...")
    audit_results = [{"check": "SMBv1_enabled", "status": "enabled"}]

    # 3. Proses Laporan
    print("[*] Correlating findings...")
    findings = correlate(scan_results, audit_results, args.target)
    
    if findings:
        print("[!] VULNERABILITIES FOUND!")
        write_reports(findings)
    else:
        print("[+] No critical vulnerabilities found.")

if __name__ == "__main__":
    main()