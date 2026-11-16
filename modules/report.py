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
    json_path = os.path.join(output_dir, f"report_{timestamp}.json")
    
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=4)
        
    print(f"\n[+] Reports saved locally in folder: {output_dir}/")