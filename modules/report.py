import os
import json
import datetime

def correlate(scan_results, audit_results, target):
    if target not in ["127.0.0.1", "localhost"]:
        return []

    combined = []
    open_ports = {
        p.get("port"): p
        for p in scan_results
        if p.get("status") == "open" or p.get("state") == "open"
    }

    for audit in audit_results:
        # Support both Member 3 real format (check_id / status == "FAIL")
        # and legacy dummy format (check == "SMBv1_enabled" / status == "enabled")
        check_id = audit.get("check_id") or audit.get("check")
        name = audit.get("name", check_id)
        status = audit.get("status")

        if check_id == "SMBv1_enabled" and status == "enabled":
            if 445 in open_ports:
                combined.append({
                    "check": "SMB Exploit Vector",
                    "status": "VULNERABLE",
                    "severity": "CRITICAL",
                    "details": "Port 445 is open AND SMBv1 is enabled. High risk.",
                    "remediation": "Disable SMBv1 immediately."
                })
            continue

        if status == "FAIL":
            related_ports = audit.get("related_ports", [])
            matched_open = [port for port in related_ports if port in open_ports]

            if matched_open:
                combined.append({
                    "check": f"{check_id}: {name} (Correlated with Open Port {matched_open})",
                    "status": "VULNERABLE",
                    "severity": "CRITICAL",
                    "details": (
                        f"Port(s) {matched_open} open AND {name} failed "
                        f"(Current: {audit.get('current_value')}, Expected: {audit.get('expected_value')})."
                    ),
                    "remediation": audit.get("remediation", "Review CIS configuration.")
                })
            else:
                combined.append({
                    "check": f"{check_id}: {name}",
                    "status": "FAIL",
                    "severity": audit.get("severity", "HIGH"),
                    "details": (
                        f"Current: {audit.get('current_value')} | "
                        f"Expected: {audit.get('expected_value')}"
                    ),
                    "remediation": audit.get("remediation", "Apply CIS benchmark remediation.")
                })

    return combined

def write_reports(results, output_dir="output"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # 1. JSON Output
    json_path = os.path.join(output_dir, f"report_{timestamp}.json")
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=4)

    # 2. Text Output
    txt_path = os.path.join(output_dir, f"report_{timestamp}.txt")
    with open(txt_path, 'w') as f:
        f.write("WINSEC AUDITOR REPORT\n")
        f.write("="*30 + "\n")
        for item in results:
            f.write(f"[{item.get('severity', 'INFO')}] {item.get('check')}\n")
            f.write(f"Details: {item.get('details')}\n")
            f.write(f"Remediation: {item.get('remediation')}\n\n")

    # 3. HTML Output
    html_path = os.path.join(output_dir, f"report_{timestamp}.html")
    with open(html_path, 'w') as f:
        f.write("<html><head><title>WinSec Auditor Report</title></head><body>")
        f.write("<h1>WinSec Auditor - Compliance Report</h1>")
        for item in results:
            f.write(f"<h3 style='color:red;'>{item.get('check')} - {item.get('severity')}</h3>")
            f.write(f"<p><b>Details:</b> {item.get('details')}</p>")
            f.write(f"<p><b>Remediation:</b> {item.get('remediation')}</p><hr>")
        f.write("</body></html>")

    print(f"\n[+] Reports saved locally in folder: {output_dir}/ (JSON, TXT, HTML)")
