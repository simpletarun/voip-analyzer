import os, subprocess, sys
r = subprocess.run([sys.executable, "-m", "py_compile",
    "src/ui/main_window.py", "src/plugins/whatsapp.py", "src/services/stun.py",
    "src/services/capturer.py", "src/services/network_analyzer.py",
    "src/database/connection.py", "src/database/repository.py",
    "src/models/packet.py", "src/config.py"], capture_output=True, text=True)
print("compile rc", r.returncode)
print(r.stdout or "(ok)")
print(r.stderr or "")
r2 = subprocess.run([sys.executable, "-m", "pytest", "-q", "tests/test_plugins.py",
                     "tests/test_stun.py"], capture_output=True, text=True)
print(r2.stdout[-400:])
print("tests rc", r2.returncode)
os.remove("_pyf.py")
print("cleanup done")
