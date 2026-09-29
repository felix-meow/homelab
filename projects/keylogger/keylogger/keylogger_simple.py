import os
import sys
import time
from datetime import datetime

def log_key(log_file="keylog.txt"):
    print("🔍 Keylogger simplu pornit.")
    print("📝 Tastează câte ceva și apasă ENTER pentru a înregistra.")
    print("⌨️  Scrie 'exit' pentru a opri.")
    
    with open(log_file, 'a') as f:
        f.write(f"\n=== KEYLOG SESSION ===\nStart: {datetime.now().isoformat()}\nUser: {os.getenv('USER', 'unknown')}\n=====================\n")
        f.flush()
    
    while True:
        try:
            line = input(">> ")
            if line.lower() == 'exit':
                break
            with open(log_file, 'a') as f:
                f.write(f"{datetime.now().isoformat()} - {line}\n")
                f.flush()
                print(f"✅ Înregistrat: {line}")
        except KeyboardInterrupt:
            break
    
    with open(log_file, 'a') as f:
        f.write(f"End: {datetime.now().isoformat()}\n=====================\n")

if __name__ == "__main__":
    log_key()
