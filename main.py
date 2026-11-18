import argparse
from core.safety import get_authorization, enforce_scope, kill_switch_check
from modules.report import correlate, write_reports
from modules.scanner import PortScanner, parse_ports, format_table
from modules.win_audit import WindowsConfigAuditor

def main():
    parser = argparse.ArgumentParser(description="WinSec Auditor: Windows Compliance Scanner")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP")
    parser.add_argument("--dry-run", action="store_true", help="Simulate scan")
    parser.add_argument("--ports", default="quick",
                        help="ports to scan: quick, windows, all, or e.g. 22,80,1-1024 (default: quick)")
    args = parser.parse_args()

    # 1. Test Keselamatan
    get_authorization()
    enforce_scope(args.target)
    kill_switch_check()

    # 2. Port scan (Member 2) - real TCP connect scan of the authorised target
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))
    if args.dry_run:
        print(f"[DRY-RUN] Would scan {len(ports)} TCP port(s) on {args.target}. Running dry-run compliance check...")
        auditor = WindowsConfigAuditor(dry_run=True)
        auditor.run_all_checks()
        auditor.print_summary()
        return

    print(f"[*] Scanning {len(ports)} port(s) on {args.target} (Ctrl+C to stop)...")
    scan_report = PortScanner().scan(args.target, ports)
    print(format_table(scan_report))
    scan_results = [f.to_dict() for f in scan_report.to_findings()]
    
    # 3. Windows Misconfiguration Audit (Member 3)
    print("[*] Auditing compliance...")
    auditor = WindowsConfigAuditor(dry_run=args.dry_run)
    audit_results = auditor.run_all_checks()
    auditor.print_summary()

    # 4. Proses Laporan
    print("[*] Correlating findings...")
    findings = correlate(scan_results, audit_results, args.target)
    
    if findings:
        print("[!] VULNERABILITIES FOUND!")
        write_reports(findings)
    else:
        print("[+] No critical vulnerabilities found.")

if __name__ == "__main__":
    main()
