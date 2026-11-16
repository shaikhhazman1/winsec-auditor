import sys

def get_authorization():
    print("="*50)
    print(" WINSEC AUDITOR - LEGAL DISCLAIMER ")
    print(" Reference: Computer Crimes Act 1997 (Malaysia)")
    print(" This tool is for authorized auditing ONLY.")
    print("="*50)
    
    confirm = input("Do you have written authorization to scan this target? (yes/no): ")
    if confirm.lower() != 'yes':
        print("[!] Authorization denied. Exiting.")
        sys.exit(1)

def enforce_scope(target):
    allowed_targets = ["127.0.0.1", "localhost"]
    
    if target not in allowed_targets:
        print(f"[!] SAFE MODE: Target '{target}' is outside allowed scope.")
        print(f"[!] Allowed targets: {allowed_targets}")
        sys.exit(1)
    print(f"[+] Scope authorized: {target}")

def kill_switch_check():
    try:
        input("[*] Press ENTER to continue, or CTRL+C to ABORT (Kill Switch)...")
    except KeyboardInterrupt:
        print("\n[!] Kill Switch activated. Aborting safely.")
        sys.exit(0)