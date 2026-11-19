# 🛡️ WinSec Auditor

**WinSec Auditor** is a local Windows compliance scanner and port auditing tool designed for ethical hackers and system administrators. It performs local reconnaissance and configuration auditing to identify potential vulnerabilities, correlating open ports with misconfigurations to generate a comprehensive security report.

## 📌 Attack Category
**Auditing** - Windows Compliance & Misconfiguration Scanner.

## 🔄 Attack Lifecycle Mapping
This tool operates within the **Reconnaissance** and **Vulnerability Analysis** phases of the ethical hacking lifecycle:
1. **Reconnaissance:** Scans for open ports (e.g., SMB port 445) on the local target.
2. **Vulnerability Analysis:** Audits the system for insecure configurations (e.g., SMBv1 enabled, weak firewall rules).
3. **Correlation:** Combines port scan results with audit results to identify critical exploit vectors (e.g., Port 445 Open + SMBv1 Enabled = Critical Risk).

## ⚙️ Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/shaikhhazman1/winsec-auditor.git
   cd winsec-auditor
   ```
2. Ensure you have Python 3.8+ installed.
   ```bash
   python --version
   ```
3. (Optional) Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```

## 🚀 Usage
Run the tool using the command line. **By default, it targets `127.0.0.1` (localhost) for safety.**

```bash
python main.py --target 127.0.0.1
```

**Flags:**
- `--target`: Specify the target IP (Default: `127.0.0.1`).
- `--dry-run`: Simulate the scan without executing audit checks (useful for testing).

## 🛡️ Ethical Considerations & Safe Defaults
- **Authorization Scope:** The tool enforces a strict scope. It will only run against `127.0.0.1` (localhost) unless explicitly modified in the code.
- **Safe Defaults:** Defaults to localhost to prevent accidental scanning of external networks.
- **Kill Switch:** Users can press `CTRL+C` at any prompt to cleanly abort the execution.
- **Data Handling:** All reports are stored locally in the `output/` directory (JSON format). The tool does **not** exfiltrate or transmit data over the network.

## 📜 Rules of Engagement (RoE)
- **Authorized Scope:** `127.0.0.1` (Localhost) only.
- **Time Windows:** To be executed during designated lab hours or with explicit permission from the system owner.
- **Permitted Techniques:** Local port scanning and configuration auditing only.
- **Prohibited Actions:** Exploiting vulnerabilities, launching Denial of Service (DoS) attacks, or scanning external IP addresses.
- **Emergency Stop:** Press `CTRL+C` to trigger the kill switch immediately.

## 📢 Responsible Disclosure
If this tool is used in a real-world scenario and discovers critical vulnerabilities, do **NOT** publish them publicly. The findings should be reported privately to the respective IT administrator or system owner within 48 hours, along with remediation steps (as provided in the report).

## ⚖️ Legal Disclaimer
**WARNING:** This tool is intended for educational purposes and authorized security auditing only. Using this tool against any system without explicit written authorization is illegal and strictly prohibited. Users are solely responsible for their actions. This project references the **Computer Crimes Act 1997 (Malaysia)** and strictly adheres to ethical hacking principles. 

## ⚠️ Limitations
- Currently only supports Windows operating systems.
- The audit module requires administrative privileges to read certain registry keys (e.g., SMBv1 status).
- The correlation engine currently only checks for SMB-related vulnerabilities (Port 445 + SMBv1). Future updates will expand this.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
