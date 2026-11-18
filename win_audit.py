import platform
import subprocess
import re
from typing import List, Dict, Any

# Safely import winreg so the repo still imports cleanly if tested on Linux/Kali
try:
    import winreg
    IS_WINDOWS = platform.system() == "Windows"
except ImportError:
    winreg = None
    IS_WINDOWS = False


class WindowsConfigAuditor:
    """Executes read-only local configuration checks on Windows 10/11 systems."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.results: List[Dict[str, Any]] = []

    def _read_registry(self, hive, subkey: str, value_name: str):
        """Read-only helper to query a Windows Registry value safely."""
        if not IS_WINDOWS or winreg is None:
            return None, "Not running on Windows OS"
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, value_name)
                return value, None
        except FileNotFoundError:
            return None, "Registry key or value not found"
        except PermissionError:
            return None, "Permission denied (Run terminal as Administrator)"
        except Exception as e:
            return None, str(e)

    def _run_readonly_cmd(self, cmd: List[str], timeout: int = 10) -> str:
        """Executes a read-only system query command without shell injection risk."""
        if not IS_WINDOWS:
            return ""
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            return proc.stdout.strip()
        except Exception:
            return ""

    def check_smbv1(self) -> Dict[str, Any]:
        """Check 1: Ensure SMBv1 Server Protocol is disabled (CIS 18.3.3)."""
        subkey = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        val, err = self._read_registry(winreg.HKEY_LOCAL_MACHINE if winreg else None, subkey, "SMB1")

        if err == "Registry key or value not found":
            status = "PASS"
            current = "Not Present (Disabled by default on modern builds)"
            severity = "LOW"
        elif err:
            status = "ERROR"
            current = err
            severity = "MEDIUM"
        elif val == 0:
            status = "PASS"
            current = "0 (Disabled)"
            severity = "LOW"
        else:
            status = "FAIL"
            current = f"{val} (Enabled)"
            severity = "HIGH"

        return {
            "check_id": "WIN-SMB-001",
            "category": "Network Security",
            "cis_reference": "CIS 18.3.3",
            "name": "SMBv1 Protocol Status",
            "status": status,
            "severity": severity,
            "current_value": current,
            "expected_value": "0 (Disabled)",
            "related_ports": [445, 139],
            "remediation": (
                "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 to 0, "
                "or run: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
            )
        }

    def check_firewall_profiles(self) -> Dict[str, Any]:
        """Check 2: Ensure Windows Defender Firewall is enabled across all profiles (CIS 9.1.1 / 9.2.1 / 9.3.1)."""
        profiles = {
            "Domain": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
            "Private": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
            "Public": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
        }
        disabled_profiles = []
        status_details = []

        for name, path in profiles.items():
            val, err = self._read_registry(winreg.HKEY_LOCAL_MACHINE if winreg else None, path, "EnableFirewall")
            if err:
                status_details.append(f"{name}: Error ({err})")
                disabled_profiles.append(name)
            elif val == 1:
                status_details.append(f"{name}: Enabled")
            else:
                status_details.append(f"{name}: Disabled")
                disabled_profiles.append(name)

        passed = len(disabled_profiles) == 0
        return {
            "check_id": "WIN-FW-002",
            "category": "Windows Defender Firewall",
            "cis_reference": "CIS 9.1.1, 9.2.1, 9.3.1",
            "name": "Windows Firewall Profile State (Domain, Private, Public)",
            "status": "PASS" if passed else "FAIL",
            "severity": "LOW" if passed else "HIGH",
            "current_value": ", ".join(status_details),
            "expected_value": "Domain: Enabled, Private: Enabled, Public: Enabled",
            "related_ports": [135, 139, 445, 3389],
            "remediation": "Enable Windows Firewall across all profiles via 'netsh advfirewall set allprofiles state on'."
        }

    def check_rdp_and_nla(self) -> Dict[str, Any]:
        """Check 3: Check if Remote Desktop (RDP) is enabled and ensure NLA is enforced (CIS 18.9.65.3.9.2)."""
        rdp_key = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
        nla_key = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

        deny_conn, err1 = self._read_registry(winreg.HKEY_LOCAL_MACHINE if winreg else None, rdp_key, "fDenyTSConnections")
        nla_val, err2 = self._read_registry(winreg.HKEY_LOCAL_MACHINE if winreg else None, nla_key, "UserAuthentication")

        if err1:
            return {
                "check_id": "WIN-RDP-003",
                "category": "Remote Access",
                "cis_reference": "CIS 18.9.65.3.9.2",
                "name": "Remote Desktop (RDP) & Network Level Authentication (NLA)",
                "status": "ERROR",
                "severity": "MEDIUM",
                "current_value": f"Error reading RDP registry: {err1}",
                "expected_value": "RDP Disabled OR (RDP Enabled with NLA = 1)",
                "related_ports": [3389],
                "remediation": "Run scanner with sufficient privileges to inspect Terminal Server registry keys."
            }

        rdp_enabled = (deny_conn == 0)
        nla_enabled = (nla_val == 1)

        if not rdp_enabled:
            status = "PASS"
            severity = "LOW"
            current = f"RDP Disabled (fDenyTSConnections=1), NLA={nla_val}"
        elif rdp_enabled and nla_enabled:
            status = "PASS"
            severity = "LOW"
            current = "RDP Enabled, NLA Enforced (UserAuthentication=1)"
        else:
            status = "FAIL"
            severity = "HIGH"
            current = f"RDP Enabled WITHOUT NLA (UserAuthentication={nla_val})"

        return {
            "check_id": "WIN-RDP-003",
            "category": "Remote Access",
            "cis_reference": "CIS 18.9.65.3.9.2",
            "name": "Remote Desktop (RDP) & Network Level Authentication (NLA)",
            "status": status,
            "severity": severity,
            "current_value": current,
            "expected_value": "RDP Disabled OR NLA Enforced (UserAuthentication=1)",
            "related_ports": [3389],
            "remediation": (
                "Disable RDP if unused, or enforce Network Level Authentication (NLA) in System Properties > "
                "Remote > 'Allow connections only from computers running Remote Desktop with NLA'."
            )
        }

    def check_uac(self) -> Dict[str, Any]:
        """Check 4: Ensure User Account Control (UAC) EnableLUA is enabled (CIS 2.3.17.1)."""
        subkey = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        enable_lua, err = self._read_registry(winreg.HKEY_LOCAL_MACHINE if winreg else None, subkey, "EnableLUA")
        consent_prompt, _ = self._read_registry(
            winreg.HKEY_LOCAL_MACHINE if winreg else None, subkey, "ConsentPromptBehaviorAdmin"
        )

        if err:
            status, severity, current = "ERROR", "MEDIUM", err
        elif enable_lua == 1 and consent_prompt in (1, 2, 5):
            status, severity = "PASS", "LOW"
            current = f"EnableLUA=1, ConsentPromptBehaviorAdmin={consent_prompt}"
        else:
            status, severity = "FAIL", "HIGH"
            current = f"EnableLUA={enable_lua}, ConsentPromptBehaviorAdmin={consent_prompt}"

        return {
            "check_id": "WIN-UAC-004",
            "category": "Privilege Escalation Controls",
            "cis_reference": "CIS 2.3.17.1",
            "name": "User Account Control (UAC) Admin Approval Mode",
            "status": status,
            "severity": severity,
            "current_value": current,
            "expected_value": "EnableLUA=1 and ConsentPromptBehaviorAdmin != 0",
            "related_ports": [],
            "remediation": (
                "Enable UAC via Control Panel > User Accounts > Change User Account Control settings, "
                "or set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA to 1."
            )
        }

    def check_defender_realtime(self) -> Dict[str, Any]:
        """Check 5: Ensure Microsoft Defender Real-Time Protection is not disabled (CIS 18.9.47.4.1.1)."""
        subkey = r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
        val, err = self._read_registry(
            winreg.HKEY_LOCAL_MACHINE if winreg else None, subkey, "DisableRealtimeMonitoring"
        )

        if err == "Registry key or value not found" or val == 0:
            status = "PASS"
            severity = "LOW"
            current = "Real-Time Monitoring Active (DisableRealtimeMonitoring is 0 or not set)"
        elif err:
            status = "ERROR"
            severity = "MEDIUM"
            current = err
        else:
            status = "FAIL"
            severity = "HIGH"
            current = f"Disabled (DisableRealtimeMonitoring={val})"

        return {
            "check_id": "WIN-DEF-005",
            "category": "Endpoint Protection",
            "cis_reference": "CIS 18.9.47.4.1.1",
            "name": "Microsoft Defender Real-Time Protection",
            "status": status,
            "severity": severity,
            "current_value": current,
            "expected_value": "Active (DisableRealtimeMonitoring=0 or absent)",
            "related_ports": [],
            "remediation": (
                "Re-enable Real-Time Protection in Windows Security > Virus & threat protection > Manage settings, "
                "or via PowerShell: Set-MpPreference -DisableRealtimeMonitoring $false"
            )
        }

    def check_password_policy(self) -> Dict[str, Any]:
        """Check 6: Ensure minimum password length (>=8) and lockout threshold are set (CIS 1.1.4 / 1.2.2)."""
        output = self._run_readonly_cmd(["net", "accounts"])
        if not output:
            return {
                "check_id": "WIN-PWD-006",
                "category": "Account Policies",
                "cis_reference": "CIS 1.1.4, 1.2.2",
                "name": "Local Password Length & Account Lockout Policy",
                "status": "ERROR",
                "severity": "MEDIUM",
                "current_value": "Unable to read 'net accounts' output",
                "expected_value": "Min Password Length >= 8, Lockout Threshold > 0",
                "related_ports": [445, 3389],
                "remediation": "Configure password and lockout policies in secpol.msc under Account Policies."
            }

        min_len_match = re.search(r"Minimum password length:\s*(\d+)", output, re.IGNORECASE)
        lockout_match = re.search(r"Lockout threshold:\s*(\w+)", output, re.IGNORECASE)

        min_len = int(min_len_match.group(1)) if min_len_match else 0
        lockout = lockout_match.group(1) if lockout_match else "Never"

        len_ok = min_len >= 8
        lockout_ok = lockout.lower() != "never" and lockout != "0"

        passed = len_ok and lockout_ok
        return {
            "check_id": "WIN-PWD-006",
            "category": "Account Policies",
            "cis_reference": "CIS 1.1.4, 1.2.2",
            "name": "Local Password Length & Account Lockout Policy",
            "status": "PASS" if passed else "FAIL",
            "severity": "LOW" if passed else "MEDIUM",
            "current_value": f"Min Length: {min_len}, Lockout Threshold: {lockout}",
            "expected_value": "Min Length >= 8, Lockout Threshold between 1 and 10 invalid attempts",
            "related_ports": [445, 3389],
            "remediation": (
                "Run 'net accounts /minpwlen:12 /lockoutthreshold:5' in an elevated prompt or configure via secpol.msc."
            )
        }

    def check_unquoted_service_paths(self) -> Dict[str, Any]:
        """Check 7: Detect Windows services with unquoted binary paths containing spaces."""
        services_key = r"SYSTEM\CurrentControlSet\Services"
        vulnerable_services = []

        if not IS_WINDOWS or winreg is None:
            return {
                "check_id": "WIN-SVC-007",
                "category": "Service Permissions & Paths",
                "cis_reference": "CIS 5.x / CWE-428",
                "name": "Unquoted Service Binary Paths",
                "status": "ERROR",
                "severity": "MEDIUM",
                "current_value": "Not running on Windows OS",
                "expected_value": "0 vulnerable services",
                "related_ports": [],
                "remediation": "Enclose service ImagePath values containing spaces in double quotes."
            }

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_key, 0, winreg.KEY_READ) as root:
                num_subkeys, _, _ = winreg.QueryInfoKey(root)
                for i in range(num_subkeys):
                    svc_name = winreg.EnumKey(root, i)
                    svc_path = f"{services_key}\\{svc_name}"
                    image_path, err = self._read_registry(winreg.HKEY_LOCAL_MACHINE, svc_path, "ImagePath")
                    if err or not isinstance(image_path, str):
                        continue

                    cleaned = image_path.strip()
                    if cleaned.startswith('"') or cleaned.lower().startswith(r"\systemroot") or cleaned.lower().startswith("system32"):
                        continue

                    exe_match = re.match(r"^(.+?\.exe)\b", cleaned, re.IGNORECASE)
                    if exe_match:
                        exe_part = exe_match.group(1)
                        if " " in exe_part:
                            vulnerable_services.append(f"{svc_name} ({exe_part})")
        except Exception as e:
            return {
                "check_id": "WIN-SVC-007",
                "category": "Service Permissions & Paths",
                "cis_reference": "CIS 5.x / CWE-428",
                "name": "Unquoted Service Binary Paths",
                "status": "ERROR",
                "severity": "MEDIUM",
                "current_value": f"Error enumerating services: {e}",
                "expected_value": "0 vulnerable services",
                "related_ports": [],
                "remediation": "Run scanner as Administrator to inspect service registry keys."
            }

        passed = len(vulnerable_services) == 0
        return {
            "check_id": "WIN-SVC-007",
            "category": "Service Permissions & Paths",
            "cis_reference": "CIS 5.x / CWE-428",
            "name": "Unquoted Service Binary Paths",
            "status": "PASS" if passed else "FAIL",
            "severity": "LOW" if passed else "MEDIUM",
            "current_value": "None detected" if passed else f"{len(vulnerable_services)} found: {', '.join(vulnerable_services[:3])}",
            "expected_value": "All service paths with spaces wrapped in double quotes",
            "related_ports": [],
            "remediation": (
                "Update HKLM\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName>\\ImagePath "
                "so the full executable path is enclosed in double quotes."
            )
        }

    def check_anonymous_sam_enumeration(self) -> Dict[str, Any]:
        """Check 8: Ensure Anonymous Enumeration of SAM Accounts and Shares is disabled (CIS 2.3.10.2 / 2.3.10.3)."""
        subkey = r"SYSTEM\CurrentControlSet\Control\Lsa"
        sam_val, err1 = self._read_registry(winreg.HKEY_LOCAL_MACHINE if winreg else None, subkey, "RestrictAnonymousSAM")
        share_val, err2 = self._read_registry(winreg.HKEY_LOCAL_MACHINE if winreg else None, subkey, "RestrictAnonymous")

        if err1 and err2:
            status, severity, current = "ERROR", "MEDIUM", err1
        elif sam_val == 1 and (share_val is None or share_val >= 1):
            status, severity = "PASS", "LOW"
            current = f"RestrictAnonymousSAM={sam_val}, RestrictAnonymous={share_val}"
        else:
            status, severity = "FAIL", "MEDIUM"
            current = f"RestrictAnonymousSAM={sam_val}, RestrictAnonymous={share_val}"

        return {
            "check_id": "WIN-LSA-008",
            "category": "Network Access & Enumeration",
            "cis_reference": "CIS 2.3.10.2, 2.3.10.3",
            "name": "Anonymous SAM & Share Enumeration Restriction",
            "status": status,
            "severity": severity,
            "current_value": current,
            "expected_value": "RestrictAnonymousSAM=1, RestrictAnonymous>=1",
            "related_ports": [139, 445],
            "remediation": (
                "Enable 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' "
                "in Local Security Policy (secpol.msc)."
            )
        }

    def run_all_checks(self) -> List[Dict[str, Any]]:
        """Runs all 8 read-only Windows configuration checks and returns the standardized list."""
        check_methods = [
            self.check_smbv1,
            self.check_firewall_profiles,
            self.check_rdp_and_nla,
            self.check_uac,
            self.check_defender_realtime,
            self.check_password_policy,
            self.check_unquoted_service_paths,
            self.check_anonymous_sam_enumeration,
        ]

        if self.dry_run:
            return [
                {
                    "check_id": f"DRY-RUN-00{idx}",
                    "category": "Dry Run Mode",
                    "cis_reference": "N/A",
                    "name": method.__name__,
                    "status": "SKIPPED",
                    "severity": "INFO",
                    "current_value": "Dry-run enabled; no system queries executed",
                    "expected_value": "N/A",
                    "related_ports": [],
                    "remediation": "Run without --dry-run to execute read-only checks."
                }
                for idx, method in enumerate(check_methods, start=1)
            ]

        self.results = [method() for method in check_methods]
        return self.results


if __name__ == "__main__":
    import json
    auditor = WindowsConfigAuditor(dry_run=False)
    findings = auditor.run_all_checks()
    print(json.dumps(findings, indent=2))