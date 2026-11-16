import os
import json
import datetime

def correlate(scan_results, audit_results, target):
    if target not in ["127.0.0.1", "localhost"]:
        return []
    
    combined = []
    # Logik mudah: Kalau port 445 open DAN SMBv1 enabled, ini bahaya (Critical)
    for port_info in scan_results:
        if port_info.get('port') == 445 and port_info.get('status') == 'open':
            for audit in audit_results:
                if audit.get('check') == 'SMBv1_enabled' and audit.get('status') == 'enabled':
                    combined.append({
                        "check": "SMB Exploit Vector",
                        "status": "VULNERABLE",
                        "severity": "CRITICAL",
                        "details": "Port 445 is open AND SMBv1 is enabled. High risk.",
                        "remediation": "Disable SMBv1 immediately."
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
