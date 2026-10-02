"""Phase 3 validation entry point.

Use the OS-specific scripts instead of importing Windows-only code on Linux:
- test_phase3_windows.py for Windows agents
- test_phase3_linux.py for Linux agents
"""

import platform
import sys


if __name__ == "__main__":
    system_name = platform.system().lower()
    if system_name == "windows":
        sys.exit(__import__("pytest").main(["test_phase3_windows.py", "-v"]))
    sys.exit(__import__("pytest").main(["test_phase3_linux.py", "-v"]))