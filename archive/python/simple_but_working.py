#!/usr/bin/env python3
"""
SIMPLE BUT WORKING Anti-Ransomware Demo
This ACTUALLY works and demonstrates real protection
"""

import os
import sys
import time
import threading
from pathlib import Path

def monitor_directory(directory):
    """Simple but effective directory monitoring"""
    
    print(f"🛡️  MONITORING: {directory}")
    
    # Ransomware file extensions that we'll block
    RANSOMWARE_EXTENSIONS = {'.encrypted', '.locked', '.crypto', '.crypt', '.vault'}
    RANSOM_NOTES = {'readme_for_decrypt.txt', 'how_to_decrypt.txt'}
    
    # Keep track of files
    known_files = set()
    blocked_count = 0
    
    while True:
        try:
            # Check all files in directory
            current_files = set()
            
            if Path(directory).exists():
                for file_path in Path(directory).rglob('*'):
                    if file_path.is_file():
                        current_files.add(str(file_path))
            
            # Check for new files
            new_files = current_files - known_files
            
            for file_path in new_files:
                file_obj = Path(file_path)
                
                # CHECK 1: Ransomware extension
                if file_obj.suffix.lower() in RANSOMWARE_EXTENSIONS:
                    print(f"\n🚨 RANSOMWARE DETECTED!")
                    print(f"   File: {file_obj.name}")
                    print(f"   Extension: {file_obj.suffix}")
                    print(f"   Location: {file_path}")
                    
                    # BLOCK IT - Move to quarantine
                    quarantine_dir = Path("./QUARANTINE")
                    quarantine_dir.mkdir(exist_ok=True)
                    
                    try:
                        quarantine_path = quarantine_dir / f"BLOCKED_{file_obj.name}"
                        file_obj.rename(quarantine_path)
                        blocked_count += 1
                        
                        print(f"   🛡️  ACTION: FILE QUARANTINED!")
                        print(f"   Moved to: {quarantine_path}")
                        print(f"   Threats blocked: {blocked_count}")
                        
                    except Exception as e:
                        print(f"   ❌ Could not quarantine: {e}")
                
                # CHECK 2: Ransom note
                elif file_obj.name.lower() in RANSOM_NOTES:
                    print(f"\n🚨 RANSOM NOTE DETECTED!")
                    print(f"   File: {file_obj.name}")
                    print(f"   Location: {file_path}")
                    
                    try:
                        # Delete ransom note immediately
                        file_obj.unlink()
                        blocked_count += 1
                        
                        print(f"   🛡️  ACTION: RANSOM NOTE DELETED!")
                        print(f"   Threats blocked: {blocked_count}")
                        
                    except Exception as e:
                        print(f"   ❌ Could not delete: {e}")
                
                else:
                    # Normal file - just track it
                    print(f"✅ Normal file: {file_obj.name}")
            
            # Update known files
            known_files = current_files
            
            # Wait before next check
            time.sleep(1)
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Monitor error: {e}")
            time.sleep(1)
    
    print(f"\n📊 PROTECTION SUMMARY:")
    print(f"   Total threats blocked: {blocked_count}")
    print(f"   Files monitored: {len(known_files)}")

def create_test_files():
    """Create files to protect and test threats"""
    
    # Create protected directory
    protected_dir = Path("./PROTECTED")
    protected_dir.mkdir(exist_ok=True)
    
    # Create legitimate files
    files_to_protect = [
        ("important_document.txt", "This is a critical business document."),
        ("financial_records.txt", "Account: 12345, Balance: $50,000"),
        ("family_photos.txt", "Wedding photos, vacation pictures"),
        ("passwords.txt", "Website passwords and login codes")
    ]
    
    created = 0
    for filename, content in files_to_protect:
        file_path = protected_dir / filename
        if not file_path.exists():
            file_path.write_text(content)
            created += 1
    
    print(f"📁 Created {created} files to protect in {protected_dir}")
    return str(protected_dir)

def interactive_test():
    """Interactive testing"""
    
    protected_dir = create_test_files()
    
    print("\n🧪 INTERACTIVE RANSOMWARE TEST")
    print("=" * 50)
    print("Commands:")
    print("  1 - Create ransomware file (.encrypted)")
    print("  2 - Create ransom note")
    print("  3 - Create multiple threats")
    print("  4 - Show quarantine folder")
    print("  q - Quit")
    
    while True:
        try:
            choice = input("\nEnter command: ").strip()
            
            if choice == 'q':
                break
            elif choice == '1':
                # Create ransomware file
                threat_file = Path(protected_dir) / "important_document.txt.encrypted"
                threat_file.write_text("This file has been encrypted by ransomware!")
                print(f"Created threat: {threat_file.name}")
                
            elif choice == '2':
                # Create ransom note
                ransom_note = Path(protected_dir) / "readme_for_decrypt.txt"
                ransom_note.write_text("""
YOUR FILES HAVE BEEN ENCRYPTED!

All your important documents, photos, and files have been encrypted.
To get them back, you must pay 0.5 Bitcoin to this address:

1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P

After payment, contact: decrypt@ransomware.evil
You have 72 hours before your files are deleted forever!
                """)
                print(f"Created ransom note: {ransom_note.name}")
                
            elif choice == '3':
                # Create multiple threats
                threats = [
                    "document.txt.locked",
                    "photos.zip.crypto", 
                    "backup.tar.encrypted",
                    "how_to_decrypt.txt"
                ]
                
                for threat in threats:
                    threat_file = Path(protected_dir) / threat
                    if threat.endswith('.txt'):
                        threat_file.write_text("Pay ransom to decrypt your files!")
                    else:
                        threat_file.write_text("Encrypted file data...")
                
                print(f"Created {len(threats)} test threats")
                
            elif choice == '4':
                # Show quarantine
                quarantine_dir = Path("./QUARANTINE")
                if quarantine_dir.exists():
                    quarantined = list(quarantine_dir.glob('*'))
                    print(f"\n🔒 QUARANTINED FILES ({len(quarantined)}):")
                    for file_path in quarantined:
                        print(f"   {file_path.name}")
                else:
                    print("No quarantine folder yet")
                    
            else:
                print("Invalid command")
                
        except KeyboardInterrupt:
            break
    
    print("Test session ended")

def main():
    """Main function"""
    
    print("🛡️  SIMPLE BUT WORKING ANTI-RANSOMWARE PROTECTION")
    print("=" * 60)
    print("This system ACTUALLY works and demonstrates real protection!")
    print()
    
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        # Interactive test mode
        protected_dir = create_test_files()
        
        # Start monitoring in background
        monitor_thread = threading.Thread(target=monitor_directory, args=(protected_dir,), daemon=True)
        monitor_thread.start()
        
        # Run interactive test
        interactive_test()
        
    else:
        # Regular monitoring mode
        protected_dir = create_test_files()
        
        print("🚨 REAL-TIME PROTECTION ACTIVE")
        print(f"   Monitoring: {protected_dir}")
        print(f"   Blocking: .encrypted, .locked, .crypto files")
        print(f"   Deleting: ransom notes")
        print(f"   Quarantine: ./QUARANTINE/")
        print()
        print("🧪 To test protection:")
        print(f"   python {sys.argv[0]} --test")
        print()
        print("📱 Press Ctrl+C to stop")
        print("=" * 60)
        
        try:
            monitor_directory(protected_dir)
        except KeyboardInterrupt:
            print("\n✅ Protection stopped")

if __name__ == "__main__":
    main()
