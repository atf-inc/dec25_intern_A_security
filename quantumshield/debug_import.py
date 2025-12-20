
import sys
import os
print(f"CWD: {os.getcwd()}")
print(f"Sys Path: {sys.path}")
print(f"Contents of CWD: {os.listdir('.')}")
print(f"Contents of quantumshield: {os.listdir('quantumshield')}")

try:
    import quantumshield
    print(f"Imported quantumshield: {quantumshield}")
    print(f"quantumshield path: {quantumshield.__path__}")
except ImportError as e:
    print(f"Failed to import quantumshield: {e}")

try:
    import quantumshield.core
    print("Imported quantumshield.core")
except ImportError as e:
    print(f"Failed to import quantumshield.core: {e}")
