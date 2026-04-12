#!/usr/bin/env python3
"""
LLMPot — SSH Host Key Generator
Generates an RSA 2048-bit key for the honeypot SSH server.
"""

import sys
from pathlib import Path
import paramiko
from config import SSH_HOST_KEY_FILE


def generate_host_key(key_path: str = SSH_HOST_KEY_FILE, bits: int = 2048) -> None:
    """Generate an RSA host key and save to file."""
    key_file = Path(key_path)

    if key_file.exists():
        print(f"[!] Host key already exists at: {key_file}")
        response = input("    Overwrite? (y/N): ").strip().lower()
        if response != "y":
            print("[*] Keeping existing key.")
            return

    print(f"[*] Generating {bits}-bit RSA host key...")
    key = paramiko.RSAKey.generate(bits)
    key.write_private_key_file(str(key_file))
    print(f"[✓] Host key saved to: {key_file}")
    print(f"    Fingerprint: {key.get_fingerprint().hex()}")


if __name__ == "__main__":
    try:
        generate_host_key()
    except Exception as e:
        print(f"[✗] Error generating key: {e}", file=sys.stderr)
        sys.exit(1)
